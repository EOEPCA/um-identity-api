from enum import Enum
from typing import Any, List, Optional

from pydantic import PositiveInt, Field

from app.models.base import APIBaseModel

POLICY_TYPES = ['user', 'client', 'role', 'time', 'regex', 'group', 'scope', 'aggregated']


class Logic(Enum):
    POSITIVE = 'POSITIVE'
    NEGATIVE = 'NEGATIVE'


class UserPermission(APIBaseModel):
    users: List[str] = Field(None, description="List of usernames")
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")


class RolePermission(APIBaseModel):
    roles: List[str] = Field(None, description="List of roles")
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")


class Permission(APIBaseModel):
    user: List[str] | List[UserPermission] = Field([], description="User based permission")
    role: List[str] | List[RolePermission] = Field([], description="Role based permission")


class DecisionStrategy(Enum):
    AFFIRMATIVE = 'AFFIRMATIVE'
    UNANIMOUS = 'UNANIMOUS'
    CONSENSUS = 'CONSENSUS'


class Resource(APIBaseModel):
    name: str = Field(description="Resource name")
    uris: List[str] = Field(description="Resource URIs")
    attributes: Optional[Any] = Field({}, description="Resource attributes")
    scopes: Optional[List[str]] = Field(["access"], description="Resource scopes")
    ownerManagedAccess: Optional[bool] = Field(False, description="Enable/Disable management by the resource owner")
    permissions: Optional[Permission] = Field(None, description="Resource permissions")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")


class Client(APIBaseModel):
    clientId: str = Field(description="Client id")
    name: Optional[str] = Field(None, description="Client name")
    description: Optional[str] = Field(None, description="Client description")
    secret: Optional[str] = Field(None, description="Client secret")
    rootUrl: Optional[str] = Field(None, description="Client root URL")
    adminUrl: Optional[str] = Field(None, description="Client admin URL")
    baseUrl: Optional[str] = Field(None, description="Client base URL")
    redirectUris: Optional[List[str]] = Field(['*'], description="Client Redirect URIs")
    webOrigins: Optional[List[str]] = Field(['*'], description="Client Web origins")
    protocol: Optional[str] = Field('openid-connect', description="Client protocol: openid-connect / SAML")
    defaultRoles: Optional[List[str]] = Field(None, description="Client Default roles")
    bearerOnly: Optional[bool] = Field(None, description="Enable/Disable Bearer only")
    consentRequired: Optional[bool] = Field(None, description="Enable/Disable Consent required")
    publicClient: Optional[bool] = Field(False, description="Disable/Enable authentication to the client")
    authorizationServicesEnabled: Optional[bool] = Field(True, description="Enable Authorization Services")
    serviceAccountsEnabled: Optional[bool] = Field(True, description="Either or not to create a Service Account for the client")
    standardFlowEnabled: Optional[bool] = Field(True, description="Enable/Disable Standard Flow")
    implicitFlowEnabled: Optional[bool] = Field(None, description="Client name")
    directAccessGrantsEnabled: Optional[bool] = Field(None, description="Enable/Disable Direct Access Grants Flow")
    oauth2DeviceAuthorizationGrantEnabled: Optional[bool] = Field(None, description="Enable/Disable OAuth2 Device Authorization Grant Flow")
    directGrantsOnly: Optional[bool] = Field(None, description="Enable/Disable Direct Grants Flow")
    resources: Optional[List[Resource]] = Field([], description="List of resources to be added to the client")


class ResourceBasedPermission(APIBaseModel):
    logic: Logic
    decisionStrategy: DecisionStrategy
    name: str
    resources: List[str]
    policies: List[str]


class ClientPolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    clients: List[str]
    description: str = ""


class AggregatedPolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    policies: List[str]
    description: str = ""


class ClientScope(APIBaseModel):
    id: str


class ScopePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    clientScopes: List[ClientScope]
    description: str = ""


class Group(APIBaseModel):
    id: str
    path: str


class GroupPolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    groups: List[Group]
    groupsClaim: str = ""
    description: str = ""


class RegexPolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    pattern: str
    targetClaim: str = ""
    description: str = ""


class Role(APIBaseModel):
    id: str


class RolePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    roles: List[Role]
    description: str = ""


class RelativeTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    notAfter: str
    notBefore: str
    description: str = ""


class DayMonthTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    dayMonth: PositiveInt
    dayMonthEnd: PositiveInt
    description: str = ""


class MonthTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    month: PositiveInt
    monthEnd: PositiveInt
    description: str = ""


class YearTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    year: PositiveInt
    yearEnd: PositiveInt
    description: str = ""


class HourTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    hour: PositiveInt
    hourEnd: PositiveInt
    description: str = ""


class MinuteTimePolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    minute: PositiveInt
    minuteEnd: PositiveInt
    description: str = ""


class UserPolicy(APIBaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS.value
    name: str
    users: List[str]


class PolicyType(Enum):
    CLIENT = 'client'
    AGGREGATE = 'aggregate'
    SCOPE = 'scope'
    GROUP = 'group'
    REGEX = 'regex'
    ROLE = 'role'
    TIME = 'time'


class ModifyClientPolicy(ClientPolicy):
    type: PolicyType


class ModifyAggregatedPolicy(AggregatedPolicy):
    type: PolicyType


class ModifyScopePolicy(ScopePolicy):
    type: PolicyType


class ModifyGroupPolicy(GroupPolicy):
    type: PolicyType


class ModifyRegexPolicy(RegexPolicy):
    type: PolicyType


class ModifyRolePolicy(RolePolicy):
    type: PolicyType


class ModifyRelativeTimePolicy(RelativeTimePolicy):
    type: PolicyType


class ModifyDayMonthTimePolicy(DayMonthTimePolicy):
    type: PolicyType


class ModifyMonthTimePolicy(MonthTimePolicy):
    type: PolicyType


class ModifyYearTimePolicy(YearTimePolicy):
    type: PolicyType


class ModifyHourTimePolicy(HourTimePolicy):
    type: PolicyType


class ModifyMinuteTimePolicy(MinuteTimePolicy):
    type: PolicyType


class ModifyUserPolicy(UserPolicy):
    type: PolicyType