from flask import Blueprint, request
from keycloak import KeycloakDeleteError, KeycloakGetError, KeycloakPostError, KeycloakPutError


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    resources = Blueprint('resources', __name__)

    @resources.route("/<client_id>/resources", methods=["GET"])
    def get_resources(client_id: str):
        try:
            response =  keycloak_client.get_resources(client_id)
            return response
        except KeycloakGetError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/resources/<resource_id>", methods=["GET"])
    def get_resource(resource_id: str):
        try:
            response =  keycloak_client.get_resource(resource_id)
            return response
        except KeycloakGetError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources", methods=["POST"])
    def register_resource(client_id: str ):
        resource = request.get_json()
        try:
            response =  keycloak_client.register_resource(resource, client_id)
            return response
        except KeycloakPostError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["PUT"])
    def update_resource(client_id: str, resource_id: str):
        resource = request.get_json()
        try:
            response =  keycloak_client.update_resource(resource_id, resource, client_id)
            return response
        except KeycloakPutError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["DELETE"])
    def delete_resource(client_id: str, resource_id: str):
        try:
            response =  keycloak_client.delete_resource(resource_id, client_id)
            return response
        except KeycloakDeleteError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    def custom_error(message, status_code): 
        return message, status_code

    return resources
