from fastapi import APIRouter

from app.keycloak_client import keycloak

router = APIRouter(
    prefix="/resources",
    tags=["Resouces"],
)


@router.get("")
def get_resources(client_id: str):
    return keycloak.get_resources(client_id)


@router.get("/resources/{resource_id}")
def get_resource(resource_id: str):
    return keycloak.get_resource(resource_id)