from typing import List

from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.log import log
from app.models.clients import POLICY_TYPES, Resource

router = APIRouter(
    prefix="/{client_id}/resources",
    tags=["Clients Resources"],
)


@router.post("")
def register_resources(client_id: str, resources: List[Resource]):
    response_list = []
    for resource in resources:
        resource_name = resource.name.replace(" ", "_")
        res = {
            "name": resource_name,
            "uris": resource.uris,
            "scopes": resource.scopes,
        }
        response_resource = keycloak.register_resource(res, client_id)
        response_list.append(response_resource)
        permissions = resource.permissions
        policy_list = []
        if permissions.role:
            policy = {
                "name": f'{resource_name}_role_policy',
                "roles": [{"id": p} for p in permissions.role]
            }
            log.info("pol " + str(policy))
            policy_response = keycloak.register_role_policy(policy, client_id)
            policy_list.append(policy_response["name"])
        if permissions.user:
            policy = {
                "name": f'{resource_name}_user_policy',
                "users": permissions.user
            }
            policy_response = keycloak.register_user_policy(policy, client_id)
            policy_list.append(policy_response["name"])
        permission_payload = {
            "type": "resource",
            "name": f'{resource_name}_permission',
            "decisionStrategy": resource.decisionStrategy,
            "resources": [
                resource_name
            ],
            "policies": policy_list
        }
        keycloak.create_client_authz_resource_based_permission(client_id, permission_payload)
    return response_list


@router.delete("/{resource_name}/all")
def delete_resource_and_policies(client_id: str, resource_name: str):
    # delete policies
    client_policies = keycloak.get_client_authz_policies(client_id)
    for policy in client_policies:
        for policy_type in POLICY_TYPES:
            if policy['name'] == f'{resource_name}_{policy_type}_policy':
                keycloak.delete_policy(policy['id'], client_id)
    # delete permissions
    permissions = keycloak.get_client_resource_permissions(client_id)
    for permission in permissions:
        if permission['name'] == f'{resource_name}_permission':
            keycloak.delete_resource_permissions(client_id, permission['id'])
    # delete resources
    resources = keycloak.get_resources(client_id)
    for resource in resources:
        if resource['name'] == resource_name:
            return keycloak.delete_resource(resource['_id'], client_id)


@router.put("/{resource_id}")
def update_resource(client_id: str, resource_id: str, resource: Resource):
    return keycloak.update_resource(resource_id, resource, client_id)


@router.delete("/{resource_id}")
def delete_resource(client_id: str, resource_id: str):
    return keycloak.delete_resource(resource_id, client_id)