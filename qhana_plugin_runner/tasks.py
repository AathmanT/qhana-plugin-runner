from datetime import datetime

from celery.result import AsyncResult
from celery.utils.log import get_task_logger
from sqlalchemy.sql.expression import select

from qhana_plugin_runner.db.db import DB
from qhana_plugin_runner.db.models.tasks import ProcessingTask

from .celery import CELERY

_name = "qhana-plugin-runner"

TASK_LOGGER = get_task_logger(_name)


# TODO add periodic cleanup task to remove old results from the database!


@CELERY.task(name=f"{_name}.save-result", bind=True, ignore_result=True)
def save_task_result(self, result: str, db_id: int):
    """Save the task result as result for the root task in the database."""
    if not isinstance(result, str):
        raise TypeError(
            f"The result of a task must be of type str to be stored in the database! (expected str but got {type(result)})"
        )

    TASK_LOGGER.debug(f"Saving result for task with db id '{db_id}'")
    task_data: ProcessingTask = ProcessingTask.get_by_id(id_=db_id)
    if task_data is None:
        # TODO use better fitting error
        raise KeyError(
            f"Could not find db entry for id {db_id}, saving task result failed!"
        )

    task_data.finished_status = "SUCCESS"
    task_data.finished_at = datetime.utcnow()
    task_data.task_result = result  # TODO type checking!

    task_data.save(commit=True)
    TASK_LOGGER.debug(f"Save result for task with db id '{db_id}' successful.")

    AsyncResult(self.request.parent_id, app=CELERY).forget()


@CELERY.task(name=f"{_name}.save-error", bind=True, ignore_result=True)
def save_task_error(self, failing_task_id: str, db_id: int):
    """Save the error as the result of the root task in the database."""
    result = AsyncResult(failing_task_id, app=CELERY)
    exc = result.result
    traceback = result.traceback

    TASK_LOGGER.error(
        f"Sub-Task {failing_task_id} of Task with db id {db_id} raised exception: {exc!r}\n{traceback}"
    )

    task_data: ProcessingTask = ProcessingTask.get_by_id(id_=db_id)

    if task_data is None:
        TASK_LOGGER.error(
            f"Cannot save error for task with db id {db_id}, no db entry found!"
        )
        return  # TODO start new error logging task or save to extra db table

    task_data.finished_status = result.state
    task_data.finished_at = datetime.utcnow()
    task_data.task_result = f"{exc!r}\n\n{traceback}"

    task_data.save(commit=True)

    result.forget()
