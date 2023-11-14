from flask import Blueprint
from keycloak import KeycloakGetError


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    resources = Blueprint('resources', __name__)

    @resources.route("/resources", methods=["OPTIONS", "GET"])
    def get_resources():
        try:
            response = keycloak_client.get_resources()
            return response
        except KeycloakGetError as error:
            return error.error_message, error.response_code
        except:
            return "Unknown server error", 500

    @resources.route("/resources/<resource_id>", methods=["OPTIONS", "GET"])
    def get_resource(resource_id: str):
        try:
            response = keycloak_client.get_resource(resource_id)
            return response
        except KeycloakGetError as error:
            return error.error_message, error.response_code
        except:
            return "Unknown server error", 500

    return resources