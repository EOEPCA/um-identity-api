from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.models.policies import SearchPolicies

router = APIRouter(
    prefix="/policies",
    tags=["Policies"],
)


@router.get("")
def search_policies(search_params: SearchPolicies):
    return keycloak.get_policies(
        search_params.resource,
        search_params.name,
        search_params.scope,
        search_params.first,
        search_params.maximum
    )