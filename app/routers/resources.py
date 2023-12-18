from fastapi import APIRouter

from app.keycloak_client import keycloak

router = APIRouter(
    prefix="/resources",
    tags=["Resouces"],
)


@router.get("")
def get_resources(client_id: str):
    return keycloak.get_resources(client_id)


@router.get("/{resource_id}")
def get_resource(resource_id: str, client_id: str, client_secret: str):
    return keycloak.get_resource(client_id, client_secret, resource_id)