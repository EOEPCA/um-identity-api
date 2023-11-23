from typing import List, Optional, Any

from pydantic import Field

from app.models.base import APIBaseModel
from app.models.permissions import DecisionStrategy, UserPermission, RolePermission


class ResourcePermission(APIBaseModel):
    user: List[str] | List[UserPermission] = Field([], description="User based permission")
    role: List[str] | List[RolePermission] = Field([], description="Role based permission")
    authenticated: bool = Field(False, description="Authenticated only permission")


class Resource(APIBaseModel):
    name: str = Field(description="Resource name")
    uris: List[str] = Field(description="Resource URIs")
    attributes: Optional[Any] = Field({}, description="Resource attributes")
    scopes: Optional[List[str]] = Field(["view"], description="Resource scopes")
    ownerManagedAccess: Optional[bool] = Field(False, description="Enable/Disable management by the resource owner")
    permissions: Optional[ResourcePermission] = Field(None, description="Resource permissions")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")