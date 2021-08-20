from collections import Generator
from io import BytesIO, TextIOWrapper, BufferedIOBase
from typing import Any, Tuple
from zipfile import ZipFile

from qhana_plugin_runner import register_additional_schemas, requests
from qhana_plugin_runner.requests import open_url


def get_files_from_zip_url(
    url: str, mode="t"
) -> Generator[Tuple[BufferedIOBase, str], Any, None]:
    with open_url(url) as taxonomy_data:
        zip_bytes = taxonomy_data.content
        # SpooledTemporaryFile cannot be used here because of https://bugs.python.org/issue26175
        tmp_buffer = BytesIO(zip_bytes)
        zip_file = ZipFile(tmp_buffer)

        for file_name in zip_file.namelist():
            with zip_file.open(file_name) as zipped_file:
                if "b" in mode:
                    yield zipped_file, file_name
                else:
                    yield TextIOWrapper(zipped_file), file_name
