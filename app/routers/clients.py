from enum import Enum
from typing import Any, List

from fastapi.exceptions import HTTPException
from fastapi import APIRouter, Depends
from keycloak import KeycloakDeleteError, KeycloakGetError, KeycloakPostError, KeycloakPutError
from pydantic import BaseModel, PositiveInt

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
)

POLICY_TYPES = ['user', 'client', 'role', 'time', 'regex', 'group', 'scope', 'aggregated']


class Resource(BaseModel):
    name: str
    uris: List[str]
    attributes: Any = {}
    scopes: List[str]
    ownerManagedAccess: bool = True


class Logic(Enum):
    NEGATIVE = 'NEGATIVE'
    POSITIVE = 'POSITIVE'


class UserPermission(BaseModel):
    users: List[str]
    logic: Logic


class RolePermission(BaseModel):
    users: List[str]
    logic: Logic


class Permission(BaseModel):
    user: List[UserPermission]
    role: List[RolePermission]


class DecisionStrategy(Enum):
    AFFIRMATIVE = 'AFFIRMATIVE'
    UNANIMOUS = 'UNANIMOUS'
    CONSENSUS = 'CONSENSUS'


class ResourcePermissions(BaseModel):
    resource: List[Resource]
    permissions: List[Permission]
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS


class Client(BaseModel):
    clientId: str
    name: str
    description: str
    rootUrl: str
    adminUrl: str
    baseUrl: str
    secret: str
    protocol: str
    defaultRoles: List[str]
    redirectUris: List[str]
    webOrigins: List[str]
    bearerOnly: bool
    consentRequired: bool
    standardFlowEnabled: bool
    implicitFlowEnabled: bool
    directAccessGrantsEnabled: bool
    serviceAccountsEnabled: bool
    oauth2DeviceAuthorizationGrantEnabled: bool
    authorizationServicesEnabled: bool
    directGrantsOnly: bool
    publicClient: bool
    resources: List[Resource]


class ResourceBasedPermission(BaseModel):
    logic: Logic
    decisionStrategy: DecisionStrategy
    name: str
    resources: List[str]
    policies: List[str]


class ClientPolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    clients: List[str]
    description: str = ""


class AggregatedPolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    policies: List[str]
    description: str = ""


class ClientScope(BaseModel):
    id: str


class ScopePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    clientScopes: List[ClientScope]
    description: str = ""


class Group(BaseModel):
    id: str
    path: str


class GroupPolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    groups: List[Group]
    groupsClaim: str = ""
    description: str = ""


class RegexPolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    pattern: str
    targetClaim: str = ""
    description: str = ""


class Role(BaseModel):
    id: str


class RolePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    roles: List[Role]
    description: str = ""


class RelativeTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    notAfter: str
    notBefore: str
    description: str = ""


class DayMonthTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    dayMonth: PositiveInt
    dayMonthEnd: PositiveInt
    description: str = ""


class MonthTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    month: PositiveInt
    monthEnd: PositiveInt
    description: str = ""


class YearTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    year: PositiveInt
    yearEnd: PositiveInt
    description: str = ""


class HourTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    hour: PositiveInt
    hourEnd: PositiveInt
    description: str = ""


class MinuteTimePolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
    name: str
    minute: PositiveInt
    minuteEnd: PositiveInt
    description: str = ""


class UserPolicy(BaseModel):
    logic: Logic = Logic.POSITIVE
    decisionStrategy: DecisionStrategy = DecisionStrategy.UNANIMOUS
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


@router.post("/{client_id}/resources")
def register_resources(keycloak, client_id: str, resources: List[ResourcePermissions]):
    # validate request before trying to register any resource
    for item in resources:
        error = _validate_register_resource(item)
        if error:
            return HTTPException(400, error)
    response_list = []
    for item in resources:
        resource = item["resource"]
        resource["name"] = resource["name"].replace(" ", "_")
        resource["scopes"] = resource['scopes'] if 'scopes' in resource and resource['scopes'] != [] else ['access']
        policies = item["permissions"]
        decision_strategy = item['decisionStrategy'] if 'decisionStrategy' in item else "UNANIMOUS"
        try:
            response_resource = keycloak.register_resource(resource, client_id)
            response_list.append(response_resource)
            policy_list = []
            for policy_type in policies:
                policy = {
                    "name": f'{resource["name"]}_{policy_type}_policy'
                }
                if isinstance(policies[policy_type], list):
                    match policy_type:
                        case 'user':
                            policy['users'] = policies[policy_type]
                        case 'role':
                            policy['roles'] = policies[policy_type]
                        case 'aggregated':
                            policy['policies'] = policies[policy_type]
                        case 'group':
                            policy['groups'] = policies[policy_type]
                else:
                    for _key in policies[policy_type]:
                        policy[_key] = policies[policy_type][_key]
                policy_list.append(policy["name"])
                keycloak.register_general_policy(policy, client_id, policy_type)
            permission_payload = {
                "type": "resource",
                "name": f'{resource["name"]}_permission',
                "decisionStrategy": decision_strategy,
                "resources": [
                    resource["name"]
                ],
                "policies": policy_list
            }
            keycloak.create_client_authz_resource_based_permission(client_id, permission_payload)
        except KeycloakPostError as e:
            return HTTPException(e.response_code, e.error_message)
    return response_list


@router.delete("/{client_id}/resources/{resource_name}/all")
def delete_resource_and_policies(keycloak, client_id: str, resource_name: str):
    try:
        # delete policies
        client_policies = keycloak.get_client_authz_policies(client_id)
        for policy in client_policies:
            for policy_type in POLICY_TYPES:
                if policy['name'] == f'{resource_name}_{policy_type}_policy':
                    keycloak.delete_policy(policy['id'], client_id)
        # delete permissions
        permissions = keycloak.get_client_resource_permissions(client_id)
        for permission in permissions:
            if permission['name'] == f'{resource_name}_permission':
                keycloak.delete_resource_permissions(client_id, permission['id'])
        # delete resources
        resources = keycloak.get_resources(client_id)
        for resource in resources:
            if resource['name'] == resource_name:
                return keycloak.delete_resource(resource['_id'], client_id)
    except KeycloakDeleteError as e:
        return HTTPException(e.response_code, e.error_message)


@router.put("/{client_id}/resources/{resource_id}")
def update_resource(keycloak, client_id: str, resource_id: str, resource: Resource):
    try:
        return keycloak.update_resource(resource_id, resource, client_id)
    except KeycloakPutError as e:
        return HTTPException(e.response_code, e.error_message)


@router.delete("/{client_id}/resources/{resource_id}")
def delete_resource(keycloak, client_id: str, resource_id: str):
    try:
        return keycloak.delete_resource(resource_id, client_id)
    except KeycloakDeleteError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/")
def create_client(keycloak, client: Client):
    if 'clientId' not in client:
        return HTTPException(400, "The field 'client_id' is mandatory")
    if 'redirectUris' not in client:
        client['redirectUris'] = ['*']
    if 'standardFlowEnabled' not in client:
        client['standardFlowEnabled'] = True
    if 'protocol' not in client:
        client['protocol'] = 'openid-connect'
    resources = client['resources'] if 'resources' in client else []
    if 'resources' in client:
        del client['resources']
    try:
        response_client = keycloak.create_client(client)
        if resources:
            response_resources = register_resources(client['clientId'], resources)
            return {
                client: response_client,
                resources: response_resources
            }
        return {
            client: response_client
        }
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.get("/{client_id}/permissions")
def get_client_authz_permissions(keycloak, client_id: str):
    try:
        return keycloak.get_client_authz_permissions(client_id)
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)


@router.get("/{client_id}/permissions/management")
def get_client_management_permissions(keycloak, client_id: str):
    try:
        return keycloak.get_client_management_permissions(client_id)
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)


@router.get("/{client_id}/permissions/resources")
def get_client_resource_permissions(keycloak, client_id: str):
    try:
        return keycloak.get_client_resource_permissions(client_id)
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/permissions/resources")
def create_client_authz_resource_based_permission(keycloak, client_id: str,
                                                  resource_based_permission: ResourceBasedPermission):
    try:
        resource_based_permission['type'] = 'resource'
        return keycloak.create_client_authz_resource_based_permission(client_id, resource_based_permission)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.get("/{client_id}/policies")
def get_client_authz_policies(keycloak, client_id: str):
    try:
        return keycloak.get_client_authz_policies(client_id)
    except KeycloakGetError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/client")
def create_client_policy(keycloak, client_id: str, client_policy: ClientPolicy):
    client_policy["type"] = "client"
    try:
        return keycloak.register_client_policy(client_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/aggregated")
def create_aggregated_policy(keycloak, client_id: str, aggregated_policy: AggregatedPolicy):
    aggregated_policy["type"] = "aggregated"
    try:
        return keycloak.register_aggregated_policy(aggregated_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/scope")
def create_client_scope_policy(keycloak, client_id: str, scope_policy: ScopePolicy):
    scope_policy["type"] = "scope"
    try:
        return keycloak.register_client_scope_policy(scope_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/group")
def create_group_policy(keycloak, client_id: str, group_policy: GroupPolicy):
    group_policy["type"] = "group"
    try:
        return keycloak.register_group_policy(group_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/regex")
def create_regex_policy(keycloak, client_id: str, regex_policy: RegexPolicy):
    regex_policy["type"] = "regex"
    try:
        return keycloak.register_regex_policy(regex_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/role")
def create_role_policy(keycloak, client_id: str, role_policy: RolePolicy):
    role_policy["type"] = "role"
    try:
        return keycloak.register_role_policy(role_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/time")
def create_time_policy(keycloak, client_id: str,
                       time_policy: RelativeTimePolicy | DayMonthTimePolicy | MonthTimePolicy |
                                    YearTimePolicy | HourTimePolicy | MinuteTimePolicy):
    time_policy["type"] = "time"
    try:
        return keycloak.register_time_policy(time_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.post("/{client_id}/policies/user")
def create_user_policy(keycloak, client_id: str, user_policy: UserPolicy):
    try:
        return keycloak.register_user_policy(user_policy, client_id)
    except KeycloakPostError as e:
        return HTTPException(e.response_code, e.error_message)


@router.put("/{client_id}/policies/{policy_id}")
def update_policy(keycloak, client_id: str, policy_id: str,
                  policy: ModifyClientPolicy | ModifyAggregatedPolicy | ModifyScopePolicy |
                          ModifyRegexPolicy | ModifyRolePolicy | ModifyRelativeTimePolicy | ModifyDayMonthTimePolicy |
                          ModifyMonthTimePolicy | ModifyYearTimePolicy | ModifyHourTimePolicy | ModifyMinuteTimePolicy |
                          ModifyUserPolicy):
    try:
        return keycloak.update_policy(client_id, policy_id, policy)
    except KeycloakPutError as e:
        return HTTPException(e.response_code, e.error_message)


@router.delete("/{client_id}/policies/{policy_id}")
def delete_policy(keycloak, client_id: str, policy_id: str):
    try:
        return keycloak.delete_policy(policy_id, client_id)
    except KeycloakDeleteError as e:
        return HTTPException(e.response_code, e.error_message)


def _validate_register_resource(resource_permissions: ResourcePermissions):
    payload_minimum_example = """
        payload example ->
            [{
                "resource":{
                    "name": "resource1",
                    "uris": ["/resource1/", "/resource2/"]
                },
                "permissions": {
                    "user": ["user1","user2"],
                }
            }]
        """
    time_options = """time must be a dictionary with one of:
                               "notAfter":"1970-01-01 00:00:00"
                               "notBefore":"1970-01-01 00:00:00"
                               "dayMonth":<day-of-month>
                               "dayMonthEnd":<day-of-month>
                               "month":<month>
                               "monthEnd":<month>
                               "year":<year>
                               "yearEnd":<year>
                               "hour":<hour>
                               "hourEnd":<hour>
                               "minute":<minute>
                               "minuteEnd":<minute>"""

    policy_types = ['user', 'client', 'role', 'time', 'regex', 'group', 'scope', 'aggregated']
    resource_accepted_fields = ['name', 'uris', 'attributes', 'ownerManagedAccess', 'resource_scopes', 'type']
    policy_accepted_fields = ['logic', 'decisionStrategy', 'name', 'description', 'groupsClaim', 'targetClaim']
    time_accepted_fields = ["notAfter", "notBefore", "dayMonth", "dayMonthEnd", "month", "monthEnd", "year", "yearEnd",
                            "hour", "hourEnd", "minute", "minuteEnd"]
    if 'resource' not in resource_permissions:
        return 'Resource field required. ' + payload_minimum_example
    if 'permissions' not in resource_permissions or resource_permissions['permissions'] == {}:
        return 'Permissions field required. ' + payload_minimum_example
    if 'name' not in resource_permissions['resource']:
        return 'Resource name required. ' + payload_minimum_example
    if 'uris' not in resource_permissions['resource']:
        return 'Resource uris required. ' + payload_minimum_example
    for resource_key in resource_permissions['resource']:
        if resource_key in resource_accepted_fields:
            continue
        else:
            return 'There are fields not accepted in "resource"'

    for key in resource_permissions['permissions']:
        if not isinstance(resource_permissions['permissions'][key], list) and not isinstance(
                resource_permissions['permissions'][key], dict):
            return "The value of {} ".format(key) + "must be a list of strings or a dictionary"
        if key not in policy_types:
            return 'Permissions type not found. Needs to be one of the following: ' + ', '.join(policy_types)
        if key == 'time':
            if not isinstance(resource_permissions['permissions']['time'], dict):
                return time_options
            for time_key in resource_permissions['permissions']['time']:
                if time_key in time_accepted_fields or time_key in policy_accepted_fields:
                    continue
                else:
                    return 'There are fields not accepted or ' + time_options
        if key == 'regex':
            if not isinstance(resource_permissions['permissions'][key], dict):
                return 'Regex must be a dictionary like {"pattern":<regex>}'
            for regex_key in resource_permissions['permissions'][key]:
                if regex_key == 'pattern' or regex_key in policy_accepted_fields:
                    continue
                else:
                    return 'The field "pattern" is not in the regex dictionary or there are fields not accepted'
        if key == 'user':
            if not isinstance(resource_permissions['permissions'][key], list):
                for user_key in resource_permissions['permissions'][key]:
                    if user_key == 'users' or user_key in policy_accepted_fields:
                        continue
                    else:
                        return 'The field "users" is not in the user dictionary or there are fields not accepted'
        if key == 'role':
            if not isinstance(resource_permissions['permissions'][key], list):
                for role_key in resource_permissions['permissions'][key]:
                    if role_key == 'roles' or role_key in policy_accepted_fields:
                        continue
                    else:
                        return 'The field "roles" is not in the role dictionary or there are fields not accepted'
        if key == 'group':
            if not isinstance(resource_permissions['permissions'][key], list):
                for group_key in resource_permissions['permissions'][key]:
                    if group_key == 'groups' or group_key in policy_accepted_fields:
                        continue
                    else:
                        return 'The field "groups" is not in the group dictionary or there are fields not accepted'
        if key == 'client-scope':
            if not isinstance(resource_permissions['permissions'][key], list):
                for client_scope_key in resource_permissions['permissions'][key]:
                    if client_scope_key in policy_accepted_fields:
                        continue
                    else:
                        return 'There are fields not accepted'

        if key == 'aggregated':
            if not isinstance(resource_permissions['permissions'][key], list):
                for aggregated_key in resource_permissions['permissions'][key]:
                    if aggregated_key == 'policies' or aggregated_key in policy_accepted_fields:
                        continue
                    else:
                        return 'The field "policies" is not in the aggregated dictionary or there are fields not accepted'

        if key == 'client':
            if not isinstance(resource_permissions['permissions'][key], list):
                for client_key in resource_permissions['permissions'][key]:
                    if client_key in policy_accepted_fields:
                        continue
                    else:
                        return 'There are fields not accepted'

    return None