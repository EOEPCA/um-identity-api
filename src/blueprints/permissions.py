from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    permissions = Blueprint('permissions', __name__)

    @permissions.route("/permissions/<client_id>", methods=["GET"])
    def get_permissions(client_id: str):
        return keycloak_client.get_permissions(client_id)
    
    @permissions.route("/permissions", methods=["POST"])
    def create_permission():
        permission = request.get_json()
        return keycloak_client.create_permission(permission)

    @permissions.route("/permissions/<permission_id>", methods=["PUT"])
    def update_permission(permission_id: str):
        permission = request.get_json()
        return keycloak_client.update_permission(permission_id, permission)

    @permissions.route("/permissions/<permission_id>", methods=["DELETE"])
    def delete_permission(permission_id: str):
        return keycloak_client.delete_permission(permission_id)

    return permissions
