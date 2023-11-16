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
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Resource based permission name")
    resources: List[str] = Field(description="Resource based permission resources")
    policies: List[str] = Field(description="Resource based permission policies")


class ClientPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Client policy name")
    clients: List[str] = Field(description="Client policy clients")
    description: Optional[str] = Field(description="Client policy description")


class AggregatedPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Aggregated Policy name")
    policies: List[str] = Field(description="Aggregated Policy policies")
    description: Optional[str] = Field(description="Aggregated Policy description")


class ClientScope(APIBaseModel):
    id: str = Field(description="Client scope id")


class ScopePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Scope policy name")
    clientScopes: List[ClientScope] = Field(description="Scope policy client scopes")
    description: Optional[str] = Field(description="Scope policy description")


class Group(APIBaseModel):
    id: str = Field(description="Group id")
    path: str = Field(description="Group path")


class GroupPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Group policy name")
    groups: List[Group] = Field(description="Group policy groups")
    groupsClaim: Optional[str] = Field(description="Group policy groups claim")
    description: Optional[str] = Field(description="Group policy description")


class RegexPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Regex policy name")
    pattern: str = Field(description="Regex policy regex pattern")
    targetClaim: Optional[str] = Field(description="Regex policy target claim")
    description: Optional[str] = Field(description="Regex policy description")


class Role(APIBaseModel):
    id: str = Field(description="Role id")


class RolePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Role policy name")
    roles: List[Role] = Field(description="Role policy roles")
    description: Optional[str] = Field(description="Role policy description")


class RelativeTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Relative time policy name")
    notAfter: str = Field(description="Relative time policy end date")
    notBefore: str = Field(description="Relative time policy start date")
    description: Optional[str] = Field(description="Relative time policy description")


class DayMonthTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Day month time policy name")
    dayMonth: PositiveInt = Field(description="Day month time policy day month start")
    dayMonthEnd: PositiveInt = Field(description="Day month time policy day month end")
    description: Optional[str] = Field(description="Day month time policy description")


class MonthTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Month time policy name")
    month: PositiveInt = Field(description="Month time policy month start")
    monthEnd: PositiveInt = Field(description="Month time policy month end")
    description: Optional[str] = Field(description="Month time policy description")


class YearTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Year time policy name")
    year: PositiveInt = Field(description="Year time policy year start")
    yearEnd: PositiveInt = Field(description="Year time policy year end")
    description: Optional[str] = Field(description="Year time policy description")


class HourTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Hour time policy name")
    hour: PositiveInt = Field(description="Hour time policy hour start")
    hourEnd: PositiveInt = Field(description="Hour time policy hour end")
    description: Optional[str] = Field(description="Hour time policy description")


class MinuteTimePolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Minute time policy name")
    minute: PositiveInt = Field(description="Minute time policy minute start")
    minuteEnd: PositiveInt = Field(description="Minute time policy minute end")
    description: Optional[str] = Field(description="Minute time policy description")


class UserPolicy(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE") 
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value, description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="User policy name")
    users: List[str] = Field(description="User policy users list")


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