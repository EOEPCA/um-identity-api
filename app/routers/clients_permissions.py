from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.models.permissions import ResourceBasedPermission, ManagementPermission

router = APIRouter(
    prefix="/{client_id}/permissions",
    tags=["Clients Permissions"],
)


@router.get("")
def get_client_authz_permissions(client_id: str):
    return keycloak.get_client_authz_permissions(client_id)


@router.get("/management")
def get_client_management_permissions(client_id: str):
    return keycloak.get_client_management_permissions(client_id)

@router.put("/management")
def get_client_management_permissions(client_id: str, managementPermission: ManagementPermission):
    return keycloak.update_client_management_permissions(client_id, managementPermission.model_dump())


@router.get("/resources")
def get_client_resource_permissions(client_id: str):
    return keycloak.get_client_resource_permissions(client_id)


@router.post("/resources")
def create_client_authz_resource_based_permission(client_id: str, resource_based_permission: ResourceBasedPermission):
    resource_based_permission = resource_based_permission.model_dump()
    resource_based_permission['type'] = 'resource'
    return keycloak.create_client_authz_resource_based_permission(client_id, resource_based_permission)