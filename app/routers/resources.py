from http.client import HTTPException

from fastapi import APIRouter
from keycloak import KeycloakGetError

router = APIRouter(
    prefix="/resources",
    tags=["resouces"],
)


@router.get("/")
def get_resources(keycloak):
    try:
        return keycloak.get_resources()
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)


@router.get("/resources/{resource_id}")
def get_resource(keycloak, resource_id: str):
    try:
        return keycloak.get_resource(resource_id)
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)