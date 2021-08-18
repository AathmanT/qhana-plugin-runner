# Copyright 2021 QHAna plugin runner contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import math
from http import HTTPStatus
from io import BytesIO, StringIO
from json import dumps, loads
from tempfile import SpooledTemporaryFile
from typing import Mapping, Optional
from zipfile import ZipFile

import marshmallow as ma
import networkx as nx
from celery.canvas import chain
from celery.result import AsyncResult
from celery.utils.log import get_task_logger
from flask import Response
from flask import redirect
from flask.app import Flask
from flask.globals import request
from flask.helpers import url_for
from flask.templating import render_template
from flask.views import MethodView
from marshmallow import EXCLUDE

from qhana_plugin_runner.api.plugin_schemas import PluginMetadataSchema
from qhana_plugin_runner.api.util import (
    FrontendFormBaseSchema,
    MaBaseSchema,
    SecurityBlueprint,
)
from qhana_plugin_runner.celery import CELERY
from qhana_plugin_runner.db.models.tasks import ProcessingTask
from qhana_plugin_runner.plugin_utils.entity_marshalling import (
    save_entities,
    load_entities,
)
from qhana_plugin_runner.requests import open_url
from qhana_plugin_runner.storage import STORE
from qhana_plugin_runner.tasks import save_task_error, save_task_result
from qhana_plugin_runner.util.plugins import QHAnaPluginBase, plugin_identifier

_plugin_name = "time-tanh"
__version__ = "v0.1.0"
_identifier = plugin_identifier(_plugin_name, __version__)


TIME_TANH_BLP = SecurityBlueprint(
    _identifier,  # blueprint name
    __name__,  # module import name!
    description="Time tanh plugin API.",
    template_folder="time_tanh_templates",
)


class TaskResponseSchema(MaBaseSchema):
    name = ma.fields.String(required=True, allow_none=False, dump_only=True)
    task_id = ma.fields.String(required=True, allow_none=False, dump_only=True)
    task_result_url = ma.fields.Url(required=True, allow_none=False, dump_only=True)


class InputParametersSchema(FrontendFormBaseSchema):
    entities_url = ma.fields.String(
        required=True,
        allow_none=False,
        metadata={
            "label": "Entities URL",
            "description": "URL to a file with entities.",
            "input_type": "textarea",
        },
    )
    attribute = ma.fields.String(
        required=True,
        allow_none=False,
        metadata={
            "label": "Attribute",
            "description": "Attribute for which the similarity shall be computed.",
            "input_type": "textarea",
        },
    )
    factor = ma.fields.Float(
        required=True,
        allow_none=False,
        metadata={
            "label": "Factor",
            "description": "Difference of values will be multiplied with this factor.",
            "input_type": "textarea",
        },
    )


@TIME_TANH_BLP.route("/")
class PluginsView(MethodView):
    """Plugins collection resource."""

    @TIME_TANH_BLP.response(HTTPStatus.OK, PluginMetadataSchema)
    @TIME_TANH_BLP.require_jwt("jwt", optional=True)
    def get(self):
        """Time tanh endpoint returning the plugin metadata."""
        return {
            "name": TimeTanh.instance.name,
            "version": TimeTanh.instance.version,
            "identifier": TimeTanh.instance.identifier,
            "root_href": url_for(f"{TIME_TANH_BLP.name}.PluginsView"),
            "title": "Time tanh similarities",
            "description": "Compares elements and returns similarity values.",
            "plugin_type": "similarity-calculation",
            "tags": ["data:loading"],
            "processing_resource_metadata": {
                "href": url_for(f"{TIME_TANH_BLP.name}.CalcSimilarityView"),
                "ui_href": url_for(f"{TIME_TANH_BLP.name}.MicroFrontend"),
                "inputs": [
                    [
                        {
                            "output_type": "entities",
                            "content_type": "application/json",
                            "name": "Entities",
                        },
                    ]
                ],
                "outputs": [
                    [
                        {
                            "output_type": "element_similarities",
                            "content_type": "application/zip",
                            "name": "Similarity values for the elements ",
                        }
                    ]
                ],
            },
        }


@TIME_TANH_BLP.route("/ui/")
class MicroFrontend(MethodView):
    """Micro frontend for the time tanh plugin."""

    example_inputs = {
        "inputStr": "Sample input string.",
    }

    @TIME_TANH_BLP.html_response(
        HTTPStatus.OK, description="Micro frontend of the time tanh plugin."
    )
    @TIME_TANH_BLP.arguments(
        InputParametersSchema(
            partial=True, unknown=EXCLUDE, validate_errors_as_result=True
        ),
        location="query",
        required=False,
    )
    @TIME_TANH_BLP.require_jwt("jwt", optional=True)
    def get(self, errors):
        """Return the micro frontend."""
        return self.render(request.args, errors)

    @TIME_TANH_BLP.html_response(
        HTTPStatus.OK, description="Micro frontend of the time tanh plugin."
    )
    @TIME_TANH_BLP.arguments(
        InputParametersSchema(
            partial=True, unknown=EXCLUDE, validate_errors_as_result=True
        ),
        location="form",
        required=False,
    )
    @TIME_TANH_BLP.require_jwt("jwt", optional=True)
    def post(self, errors):
        """Return the micro frontend with prerendered inputs."""
        return self.render(request.form, errors)

    def render(self, data: Mapping, errors: dict):
        schema = InputParametersSchema()
        return Response(
            render_template(
                "time_tanh_template.html",
                name=TimeTanh.instance.name,
                version=TimeTanh.instance.version,
                schema=schema,
                values=data,
                errors=errors,
                process=url_for(f"{TIME_TANH_BLP.name}.CalcSimilarityView"),
                example_values=url_for(
                    f"{TIME_TANH_BLP.name}.MicroFrontend", **self.example_inputs
                ),
            )
        )


@TIME_TANH_BLP.route("/process/")
class CalcSimilarityView(MethodView):
    """Start a long running processing task."""

    @TIME_TANH_BLP.arguments(InputParametersSchema(unknown=EXCLUDE), location="form")
    @TIME_TANH_BLP.response(HTTPStatus.OK, TaskResponseSchema())
    @TIME_TANH_BLP.require_jwt("jwt", optional=True)
    def post(self, arguments):
        """Start the calculation task."""
        db_task = ProcessingTask(
            task_name=calculation_task.name, parameters=dumps(arguments)
        )
        db_task.save(commit=True)

        # all tasks need to know about db id to load the db entry
        task: chain = calculation_task.s(db_id=db_task.id) | save_task_result.s(
            db_id=db_task.id
        )
        # save errors to db
        task.link_error(save_task_error.s(db_id=db_task.id))
        result: AsyncResult = task.apply_async()

        db_task.task_id = result.id
        db_task.save(commit=True)

        return redirect(
            url_for("tasks-api.TaskView", task_id=str(result.id)), HTTPStatus.SEE_OTHER
        )


class TimeTanh(QHAnaPluginBase):

    name = _plugin_name
    version = __version__

    def __init__(self, app: Optional[Flask]) -> None:
        super().__init__(app)

    def get_api_blueprint(self):
        return TIME_TANH_BLP

    def get_requirements(self) -> str:
        return ""


TASK_LOGGER = get_task_logger(__name__)


@CELERY.task(name=f"{TimeTanh.instance.identifier}.calculation_task", bind=True)
def calculation_task(self, db_id: int) -> str:
    # get parameters

    TASK_LOGGER.info(f"Starting new time tanh calculation task with db id '{db_id}'")
    task_data: Optional[ProcessingTask] = ProcessingTask.get_by_id(id_=db_id)

    if task_data is None:
        msg = f"Could not load task data with id {db_id} to read parameters!"
        TASK_LOGGER.error(msg)
        raise KeyError(msg)

    entities_url: Optional[str] = loads(task_data.parameters or "{}").get(
        "entities_url", None
    )
    TASK_LOGGER.info(f"Loaded input parameters from db: entities_url='{entities_url}'")
    attribute: Optional[str] = loads(task_data.parameters or "{}").get("attribute", None)
    TASK_LOGGER.info(f"Loaded input parameters from db: attribute='{attribute}'")
    factor: Optional[float] = loads(task_data.parameters or "{}").get("factor", None)
    TASK_LOGGER.info(f"Loaded input parameters from db: factor='{factor}'")

    # load data from file

    with open_url(entities_url) as entities_data:
        entities = list(load_entities(entities_data, "application/json"))

    # calculate similarity values for all possible value pairs

    similarities = {}

    for i in range(len(entities)):
        for j in range(i, len(entities)):
            ent1 = entities[i]
            ent2 = entities[j]

            if attribute in ent1 and attribute in ent2:
                val1 = int(ent1[attribute])
                val2 = int(ent2[attribute])

                sim = 1 - math.tanh(math.fabs((val1 - val2)) * factor)

                if (val1, val2) not in similarities and (val2, val1) not in similarities:
                    similarities[(val1, val2)] = {
                        "ID": str(val1) + "_" + str(val2),
                        "href": "",
                        "value_1": val1,
                        "value_2": val2,
                        "similarity": sim,
                    }

    with SpooledTemporaryFile(mode="w") as file:
        save_entities(similarities.values(), file, "application/json")

        STORE.persist_task_result(
            db_id,
            file,
            "similarities.json",
            "element_similarities",
            "application/json",
        )

    return "Result stored in file"
