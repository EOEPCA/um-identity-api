from fastapi import Depends, APIRouter
from pydantic import BaseModel, PositiveInt

router = APIRouter(
    prefix="/policies",
    tags=["policies"],
)

class SearchPolicies(BaseModel):
    resource: str = ''
    name: str = ''
    uri: str = ''
    first: PositiveInt = 0
    maximum: int = -1

@router.get("/")
def search_policies(keycloak, search_params: SearchPolicies):
    return keycloak.get_policies(
        search_params.resource,
        search_params.name,
        search_params.scope,
        search_params.first,
        search_params.maximum
    )