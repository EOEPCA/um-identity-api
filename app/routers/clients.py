from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.models.clients import Client
from app.routers.clients_resources import register_resources

router = APIRouter(
    prefix="/clients",
    tags=["Clients"]
)


@router.post("")
def create_client(client: Client):
    resources = client.resources
    client_dict = client.model_dump()
    del client_dict['resources']
    response_client = keycloak.create_client(client_dict)
    response = {
        "client": response_client
    }
    if resources:
        response_resources = register_resources(client.clientId, resources)
        response["resources"] = response_resources
    return response