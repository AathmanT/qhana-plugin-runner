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

# originally from <https://github.com/buehlefs/flask-template/>

"""Module containing Basic Auth security features for the API."""
import os
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from apispec.core import APISpec
from apispec.utils import deepupdate
from flask.app import Flask
from flask.globals import current_app, request
from flask_smorest import Api, abort
from flask_babel import gettext
from warnings import warn
from functools import wraps


"""Basic Auth security scheme."""
BASIC_AUTH_SCHEME = {
    "type": "http",
    "scheme": "basic",

}

"""Security schemes to be added to the swagger.json api documentation."""
SECURITY_SCHEMES = {
    "basicAuth": BASIC_AUTH_SCHEME
}


RT = TypeVar("RT")

username = os.getenv('QHANA_USERNAME')
password = os.getenv('QHANA_PWD')


def verify_basic_auth(auth):
    if auth and auth.username == username and auth.password == password:
        return True
    else:
        raise Exception("Login invalid")


class BasicAuthMixin:
    """Extend Blueprint to add security documentation and Basic Auth handling"""
    def require_auth(
        self,
        security_scheme: Union[str, Dict[str, List[Any]]],
        *,
        optional: bool = False,
    ) -> Callable[[Callable[..., RT]], Callable[..., RT]]:
        """Decorator validating Basic Auth and documenting them for openapi specification (only version 3...)."""

        if isinstance(security_scheme, str):
            security_scheme = {security_scheme: []}

        def decorator(func: Callable[..., RT]) -> Callable[..., RT]:
            # map to names that are less likely to have collisions with user defined arguments!
            _basic_auth_optional = optional

            @wraps(func)
            def wrapper(*args: Any, **kwargs) -> RT:
                try:
                    auth = request.authorization
                    verify_basic_auth(auth)
                except Exception as exc:
                    abort(401, message=gettext("Couldn't verify your login"))

                    current_app.handle_user_exception(exc)
                return func(*args, **kwargs)

                # else:
                #     return make_response("Couldn't verfiy your login", 401,
                #                          {"WWW-Authenticate": "Basic realm='Login required!'"})

            # Store doc in wrapper function
            # The deepcopy avoids modifying the wrapped function doc
            wrapper._apidoc = deepcopy(getattr(func, "_apidoc", {}))
            security_schemes = wrapper._apidoc.setdefault("security", [])
            if _basic_auth_optional:
                # also add empty security scheme for optional jwt tokens
                security_schemes.append({})
            security_schemes.append(security_scheme)

            return wrapper
        return decorator

    def _prepare_security_doc(
        self,
        doc: Dict[str, Any],
        doc_info: Dict[str, Any],
        *,
        api: Api,
        app: Flask,
        spec: APISpec,
        method: str,
        **kwargs,
    ):
        """Actually prepare the documentation."""
        operation: Optional[List[Dict[str, List[Any]]]] = doc_info.get("security")
        if operation:
            available_schemas: Dict[str, Any] = (
                spec.to_dict().get("components").get("securitySchemes")
            )
            for scheme in operation:
                if not scheme:
                    continue  # encountered empty schema for optional security
                schema_name = next(iter(scheme.keys()))
                if schema_name not in available_schemas:
                    warn(
                        f"The schema '{scheme}' is not specified in the available securitySchemes."
                    )
            doc = deepupdate(doc, {"security": operation})
        return doc
