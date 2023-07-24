from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    permissions = Blueprint('permissions', __name__)

    @permissions.route("/client_authz_permissions/<client_id>", methods=["GET"])
    def get_client_authz_permissions(client_id: str):
        return keycloak_client.get_client_authz_permissions(client_id)
    
    @permissions.route("/client_management_permissions/<client_id>", methods=["GET"])
    def get_client_management_permissions(client_id: str):
        return keycloak_client.get_client_management_permissions(client_id)
    
    @permissions.route("/client_authz_resource_permissions/<client_id>", methods=["GET"])
    def get_client_resource_permissions(client_id: str):
        return keycloak_client.get_client_resource_permissions(client_id)
    
    #@permissions.route("/client_authz_scope_permissions/<client_id>/<scope_id>", methods=["GET"])
    #def get_client_authz_scope_permissions(client_id: str, scope_id: str):
    #    return keycloak_client.get_client_authz_scope_permissions(client_id, scope_id)
    
    #@permissions.route("/client_authz_scope_permissions/<client_id>", methods=["POST"])
    #def create_client_authz_scope_based_permissions(client_id: str):
    #    payload = request.get_json()
    #    return keycloak_client.create_client_authz_scope_based_permission(client_id, payload)
    
    @permissions.route("/client_authz_resource_permissions/<client_id>", methods=["POST"])
    def create_client_authz_resource_based_permission(client_id: str):
        payload = request.get_json()
        return keycloak_client.create_client_authz_resource_based_permission(client_id, payload)

    @permissions.route("/client_management_permissions/<client_id>", methods=["PUT"])
    def update_client_management_permissions(client_id: str):
        payload = request.get_json()
        return keycloak_client.update_client_management_permissions(client_id, payload)
    
    @permissions.route("/client_authz_resource_permissions/<client_id>/<permission_id>", methods=["PUT"])
    def update_client_authz_resource_permission(client_id: str, permission_id):
        payload = request.get_json()
        return keycloak_client.update_client_authz_resource_permission(client_id, payload, permission_id)

    @permissions.route("/client_authz_scope_permissions/<client_id>/<scope_id>", methods=["PUT"])
    def update_client_authz_scope_permissions(client_id: str, scope_id):
        payload = request.get_json()
        return keycloak_client.update_client_authz_scope_permission(client_id,  payload, scope_id)

    return permissions
