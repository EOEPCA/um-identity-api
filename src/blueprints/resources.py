from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    resources = Blueprint('resources', __name__)

    @resources.route("/<client_id>/resources", methods=["GET"])
    def get_resources(client_id: str):
        return keycloak_client.get_resources(client_id)

    @resources.route("/resources/<resource_id>", methods=["GET"])
    def get_resource(resource_id: str):
        return keycloak_client.get_resource(resource_id)

    @resources.route("/<client_id>/resources", methods=["POST"])
    def register_resource(client_id: str ):
        resource = request.get_json()
        return keycloak_client.register_resource(resource, client_id)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["PUT"])
    def update_resource(client_id: str, resource_id: str):
        resource = request.get_json()
        return keycloak_client.update_resource(resource_id, resource, client_id)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["DELETE"])
    def delete_resource(client_id: str, resource_id: str):
        return keycloak_client.delete_resource(resource_id, client_id)

    return resources
