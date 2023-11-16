from enum import Enum
from typing import List, Optional

from pydantic import PositiveInt, Field

from app.models.base import APIBaseModel


class PolicyType(Enum):
    ROLE = 'role'
    USER = 'user'
    CLIENT = 'client'
    AGGREGATE = 'aggregate'
    SCOPE = 'scope'
    GROUP = 'group'
    REGEX = 'regex'
    TIME = 'time'


class Logic(Enum):
    POSITIVE = 'POSITIVE'
    NEGATIVE = 'NEGATIVE'


class UserPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    users: List[str] = Field(None, description="List of usernames")


class RolePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    roles: List[str] = Field(None, description="List of roles")


class SearchPolicies(APIBaseModel):
    resource: str = ''
    name: str = ''
    uri: str = ''
    first: PositiveInt = 0
    maximum: int = -1