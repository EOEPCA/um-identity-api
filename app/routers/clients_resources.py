from typing import List

from fastapi import APIRouter, HTTPException

from app.keycloak_client import keycloak
from app.log import logger
from app.models.policies import PolicyType
from app.models.resources import Resource
from app.routers.resources import get_resources

router = APIRouter(
    prefix="/{client_id}/resources",
    tags=["Clients Resources"],
)


@router.post("")
def register_resources(client_id: str, resources: List[Resource]):
    response_list = []
    for resource in resources:
        if resource.name.lower() == "default resource":
            client_resources = get_resources(client_id)
            default_resource = None
            for client_resource in client_resources:
                if client_resource["name"].lower() == "default resource":
                    default_resource = client_resource
            if default_resource:
                # update default resource
                default_resource["scopes"] = resource.scopes
                update_resource(client_id=client_id, resource_id=default_resource['_id'], resource=default_resource)
                response_list.append(default_resource)
            else:
                # create default resource
                res = {
                    "name": resource.name,
                    "uris": resource.uris,
                    "scopes": resource.scopes,
                }
                response_resource = keycloak.register_resource(client_id, res)
                response_list.append(response_resource)
            permission_payload = {
                "type": "resource",
                "name": f'{resource.name} Permission',
                "decisionStrategy": "UNANIMOUS",
                "resources": [
                    resource.name
                ],
                "policies": ["Default Policy"]
            }
            keycloak.create_client_authz_resource_based_permission(client_id, permission_payload)
        else:
            res = {
                "name": resource.name,
                "uris": resource.uris,
                "scopes": resource.scopes,
            }
            response_resource = keycloak.register_resource(client_id, res)
            response_list.append(response_resource)
            permissions = resource.permissions
            policy_list = []
            if permissions.role:
                policy = {
                    "name": f'{resource.name} Role Policy',
                    "roles": [{"id": p} for p in permissions.role]
                }
                policy_response = keycloak.register_role_policy(client_id, policy)
                print(policy_response)
                policy_list.append(policy_response["name"])
            if permissions.user:
                policy = {
                    "name": f'{resource.name} User Policy',
                    "users": permissions.user
                }
                policy_response = keycloak.register_user_policy(client_id, policy)
                print(policy_response)
                policy_list.append(policy_response["name"])
            print(policy_list)
            permission_payload = {
                "type": "resource",
                "name": f'{resource.name} Permission',
                "decisionStrategy": resource.decisionStrategy,
                "resources": [
                    resource.name
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
        for policy_type in [e.value for e in PolicyType]:
            if policy['name'].lower() == f'{resource_name} {policy_type} policy'.lower():
                keycloak.delete_policy(client_id, policy['id'])
    # delete permissions
    permissions = keycloak.get_client_resource_permissions(client_id)
    for permission in permissions:
        if permission['name'].lower() == f'{resource_name} permission'.lower():
            keycloak.delete_resource_permissions(client_id, permission['id'])
    # delete resources
    resources = keycloak.get_resources(client_id)
    for resource in resources:
        if resource['name'].lower() == resource_name.lower():
            return keycloak.delete_resource(client_id, resource['_id'])


@router.put("/{resource_id}")
def update_resource(client_id: str, resource_id: str, resource: Resource):
    return keycloak.update_resource(client_id, resource_id, resource.model_dump())


@router.delete("/{resource_id}")
def delete_resource(client_id: str, resource_id: str):
    return keycloak.delete_resource(client_id, resource_id)