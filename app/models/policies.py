from pydantic import PositiveInt

from app.models.base import APIBaseModel


class SearchPolicies(APIBaseModel):
    resource: str = ''
    name: str = ''
    uri: str = ''
    first: PositiveInt = 0
    maximum: int = -1