#!/usr/bin/env python3

import json
import logging
import os
from random import choice
from string import ascii_lowercase

from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
from keycloak import KeycloakConnectionError

import blueprints.permissions as permissions
import blueprints.policies as policies
import blueprints.resources as resources
import identityutils.logger as logger
from identityutils.configuration import load_configuration
from identityutils.keycloak_client import KeycloakClient
from retry.api import retry_call

mode = os.environ.get('FLASK_ENV')
if mode == 'develop':
    config_file = "config.ini"
elif mode == 'demo':
    config_file = "config.demo.ini"
elif mode == 'production':
    config_file = "config.production.ini"
else:
    config_file = "config.ini"
config_path = os.path.join(os.path.dirname(__file__), "../conf/", config_file)

logger.Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../conf/logging.yaml"))
logger = logging.getLogger("IDENTITY_API")


def identity_api(config, keycloak):
    api = Flask(__name__)
    api.secret_key = ''.join(choice(ascii_lowercase) for _ in range(30))  # Random key
    api.register_blueprint(resources.construct_blueprint(keycloak_client=keycloak))
    api.register_blueprint(policies.construct_blueprint(keycloak_client=keycloak))
    api.register_blueprint(permissions.construct_blueprint(keycloak_client=keycloak))

    swagger_spec_resources = json.load(open(os.path.join(os.path.dirname(__file__), "../conf/swagger.json")))
    swaggerui_resources_blueprint = get_swaggerui_blueprint(
        config.get('Swagger', 'swagger_url'),
        config.get('Swagger', 'swagger_api_url'),
        config={
            'app_name': config.get('Swagger', 'swagger_app_name'),
            'spec': swagger_spec_resources
        },
    )
    api.register_blueprint(swaggerui_resources_blueprint)

    return api


def keycloak_client(config):
    logger.info("Starting Keycloak client...")
    return KeycloakClient(server_url=config.get("Keycloak", "auth_server_url"),
                          realm=config.get("Keycloak", "realm"),
                          resource_server_endpoint=config.get("Keycloak", "resource_server_endpoint"),
                          username=config.get("Keycloak", "admin_username"),
                          password=config.get("Keycloak", "admin_password")
                          )


def create_app():
    """Create a Flask application using the app factory pattern."""
    config = load_configuration(config_path)
    keycloak = retry_call(keycloak_client, fargs=[config], exceptions=KeycloakConnectionError, delay=1, backoff=1.5,
                          jitter=(1, 2), logger=logger)
    return identity_api(config, keycloak)
