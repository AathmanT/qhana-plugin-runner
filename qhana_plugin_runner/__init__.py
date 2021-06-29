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

"""Root module containing the flask app factory."""

from json import load as load_json
from logging import WARNING, Formatter, Handler, Logger, getLogger
from logging.config import dictConfig
from os import environ, makedirs
from pathlib import Path
from typing import Any, Dict, IO, Mapping, Optional, cast

import click
from flask.app import Flask
from flask.cli import FlaskGroup
from flask.config import Config
from flask.logging import default_handler
from flask_cors import CORS
from tomlkit import parse as parse_toml

from . import api, babel, celery, db
from .api import jwt
from .util.config import DebugConfig, ProductionConfig
from .util.plugins import register_plugins

# change this to change tha flask app name and the config env var prefix
# must not contain any spaces!
APP_NAME = __name__
CONFIG_ENV_VAR_PREFIX = APP_NAME.upper().replace("-", "_").replace(" ", "_")


def load_toml(file_like: IO[Any]) -> Mapping[str, Any]:
    return parse_toml("\n".join(file_like.readlines()))


def create_app(test_config: Optional[Dict[str, Any]] = None):
    """Flask app factory."""
    # create and configure the app
    app = Flask(APP_NAME, instance_relative_config=True)

    # Start Loading config #################

    # load defaults
    config = cast(Config, app.config)
    flask_env = cast(Optional[str], config.get("ENV"))
    if flask_env == "production":
        config.from_object(ProductionConfig)
    elif flask_env == "development":
        config.from_object(DebugConfig)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        config.from_pyfile("config.py", silent=True)
        # also try to load json config
        config.from_file("config.json", load=load_json, silent=True)
        # also try to load toml config
        config.from_file("config.toml", load=load_toml, silent=True)
        # load config from file specified in env var
        config.from_envvar(f"{CONFIG_ENV_VAR_PREFIX}_SETTINGS", silent=True)
        # TODO load some config keys directly from env vars
    else:
        # load the test config if passed in
        config.from_mapping(test_config)

    # End Loading config #################

    # Configure logging
    log_config = cast(Optional[Dict[Any, Any]], config.get("LOG_CONFIG"))
    if log_config:
        # Apply full log config from dict
        dictConfig(log_config)
    else:
        # Apply smal log config to default handler
        log_severity = max(0, config.get("DEFAULT_LOG_SEVERITY", WARNING))
        # use percent for backwards compatibility in case of errors
        log_format_style = cast(str, config.get("DEFAULT_LOG_FORMAT_STYLE", "%"))
        log_format = cast(Optional[str], config.get("DEFAULT_LOG_FORMAT"))
        date_format = cast(Optional[str], config.get("DEFAULT_LOG_DATE_FORMAT"))
        if log_format:
            formatter = Formatter(log_format, style=log_format_style, datefmt=date_format)
            default_logging_handler = cast(Handler, default_handler)
            default_logging_handler.setFormatter(formatter)
            default_logging_handler.setLevel(log_severity)
            root = getLogger()
            root.addHandler(default_logging_handler)
            app.logger.removeHandler(default_logging_handler)

    logger: Logger = app.logger
    logger.info(
        f"Configuration loaded. Possible config locations are: 'config.py', 'config.json', Environment: '{CONFIG_ENV_VAR_PREFIX}_SETTINGS'"
    )

    if config.get("SECRET_KEY") == "debug_secret":
        logger.error(
            'The configured SECRET_KEY="debug_secret" is unsafe and must not be used in production!'
        )

    # ensure the instance folder exists
    try:
        makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # Begin loading extensions and routes

    babel.register_babel(app)

    celery.register_celery(app)

    db.register_db(app)

    jwt.register_jwt(app)
    api.register_root_api(app)

    # register plugins, AFTER registering the API!
    register_plugins(app)

    # allow cors requests everywhere (CONFIGURE THIS TO YOUR PROJECTS NEEDS!)
    CORS(app)

    if config.get("DEBUG", False):
        # Register debug routes when in debug mode
        from .util.debug_routes import register_debug_routes

        register_debug_routes(app)

    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """Cli entry point for autodoc tooling."""
    pass
