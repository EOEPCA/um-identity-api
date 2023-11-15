from fastapi import APIRouter

from app.keycloak_client import keycloak

router = APIRouter(
    prefix="/resources",
    tags=["Resouces"],
)


@router.get("")
def get_resources():
    return keycloak.get_resources()


@router.get("/resources/{resource_id}")
def get_resource(resource_id: str):
    return keycloak.get_resource(resource_id)