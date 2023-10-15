#!/usr/bin/env python3

import json
import logging
import os
from random import choice
from string import ascii_lowercase

from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
from keycloak import KeycloakConnectionError
from urllib3.exceptions import NewConnectionError

import blueprints.permissions as permissions
import blueprints.policies as policies
import blueprints.resources as resources
import identityutils.logger as logger
from identityutils.configuration import load_configuration
from identityutils.keycloak_client import KeycloakClient
from retry.api import retry_call
from flask_healthz import healthz

logger.Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../conf/logging.yaml"))
logger = logging.getLogger("IDENTITY_API")

mode = os.environ.get('FLASK_ENV')
logger.info("Starting app in mode: " + str(mode))
if mode == 'develop':
    config_file = "config.develop.ini"
elif mode == 'demo':
    config_file = "config.demo.ini"
elif mode == 'production':
    config_file = "config.production.ini"
else:
    config_file = "config.ini"
config_path = os.path.join(os.path.dirname(__file__), "../conf/", config_file)

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for _ in range(30))  # Random key
app.config['HEALTHZ'] = {
    "live": lambda: None,
    "ready": lambda: None
}

def register_endpoints(config, keycloak):
    app.register_blueprint(resources.construct_blueprint(keycloak_client=keycloak))
    app.register_blueprint(policies.construct_blueprint(keycloak_client=keycloak))
    app.register_blueprint(permissions.construct_blueprint(keycloak_client=keycloak))
    app.register_blueprint(healthz, url_prefix="/health")
    swagger_spec_resources = json.load(open(os.path.join(os.path.dirname(__file__), "../conf/swagger.json")))
    swaggerui_resources_blueprint = get_swaggerui_blueprint(
        config.get('Swagger', 'swagger_url'),
        config.get('Swagger', 'swagger_api_url'),
        config={
            'app_name': config.get('Swagger', 'swagger_app_name'),
            'spec': swagger_spec_resources
        },
    )
    app.register_blueprint(swaggerui_resources_blueprint)


def keycloak_client(config):
    logger.info("config: " + str(config))
    auth_server_url = config.get("Keycloak", "auth_server_url")
    realm = config.get("Keycloak", "realm")
    logger.info("Starting Keycloak client for: " + str(auth_server_url) + " realm: " + str(realm))
    return KeycloakClient(server_url=auth_server_url,
                          realm=realm,
                          username=config.get("Keycloak", "admin_username"),
                          password=config.get("Keycloak", "admin_password")
                          )


def create_app():
    """Create a Flask application using the app factory pattern."""
    config = load_configuration(config_path)
    keycloak = retry_call(keycloak_client, fargs=[config], exceptions=(KeycloakConnectionError, NewConnectionError),
                          delay=0.5, backoff=1.2, jitter=(1, 2), logger=logger)
    register_endpoints(config, keycloak)
    return app