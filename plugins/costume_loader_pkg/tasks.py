import json
from tempfile import SpooledTemporaryFile
from typing import Optional

import flask
from celery.utils.log import get_task_logger
from plugins.costume_loader_pkg.backend.attribute import Attribute
from plugins.costume_loader_pkg.backend.database import Database
from plugins.costume_loader_pkg.backend.entityService import EntityService

from plugins.costume_loader_pkg import CostumeLoader
from plugins.costume_loader_pkg.schemas import (
    InputParameters,
    InputParametersSchema,
    MuseEntitySchema,
)
from qhana_plugin_runner.celery import CELERY
from qhana_plugin_runner.db.models.tasks import ProcessingTask
from qhana_plugin_runner.storage import STORE

TASK_LOGGER = get_task_logger(__name__)

basiselement_attrs = [
    Attribute.basiselement,
    Attribute.design,
    Attribute.form,
    Attribute.trageweise,
    Attribute.zustand,
    Attribute.funktion,
    Attribute.material,
    Attribute.materialeindruck,
    Attribute.farbe,
    Attribute.farbeindruck,
]


@CELERY.task(name=f"{CostumeLoader.instance.identifier}.costume_loading_task", bind=True)
def costume_loading_task(self, db_id: int) -> str:
    TASK_LOGGER.info(f"Starting new demo task with db id '{db_id}'")
    task_data: Optional[ProcessingTask] = ProcessingTask.get_by_id(id_=db_id)
    param_schema = InputParametersSchema()
    input_params: InputParameters = param_schema.loads(task_data.parameters)

    es = EntityService()

    plan = [
        input_params.aggregator,
        input_params.transformer,
    ]
    plan.extend(
        [
            (
                input_params.attributes[i],
                input_params.element_comparers[i],
                input_params.attribute_comparers[i],
                input_params.empty_attribute_actions[i],
                input_params.filters[i],
            )
            for i in range(len(input_params.attributes))
        ]
    )

    es.add_plan(plan)

    app = flask.current_app

    db = Database()
    db.open_with_params(
        host=app.config.get("COSTUME_LOADER_DB_HOST"),
        user=app.config.get("COSTUME_LOADER_DB_USER"),
        password=app.config.get("COSTUME_LOADER_DB_PASSWORD"),
        database=app.config.get("COSTUME_LOADER_DB_DATABASE"),
    )

    if input_params.subset is None:
        filter_rules = {
            attr: [filter_rule]
            for attr, filter_rule in zip(input_params.attributes, input_params.filters)
        }

        print("Filter rules:", filter_rules)
        es.create_entities(db)
    else:
        for attr in input_params.attributes:
            if attr in basiselement_attrs:
                raise ValueError(
                    "When a subset is selected you cannot load basiselement attributes such as: "
                    + attr.name
                )

        es.create_subset(input_params.subset, db)

    entity_schema = MuseEntitySchema()

    entities = [entity_schema.dump(entity) for entity in es.allEntities]

    entities_json = json.dumps(entities)

    with SpooledTemporaryFile(mode="w") as output:
        output.write(entities_json)
        STORE.persist_task_result(
            db_id, output, "entities.json", "costume-loader-output", "application/json"
        )

    return "result: " + entities_json
