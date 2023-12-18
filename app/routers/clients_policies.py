from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.models.permissions import ClientPermission, AggregatedPermission, \
    ScopePermission, GroupPermission, RegexPermission, RolePermission, RelativeTimePermission, YearTimePermission, \
    HourTimePermission, \
    DayMonthTimePermission, MonthTimePermission, MinuteTimePermission, UserPermission, ModifyClientPermission, \
    ModifyRegexPermission, \
    ModifyMonthTimePermission, ModifyUserPermission, ModifyAggregatedPermission, ModifyRolePermission, \
    ModifyYearTimePermission, \
    ModifyRelativeTimePermission, ModifyScopePermission, ModifyHourTimePermission, ModifyDayMonthTimePermission, \
    ModifyMinuteTimePermission

router = APIRouter(
    prefix="/{client_id}/policies",
    tags=["Clients Policies"],
)


@router.get("")
def get_client_authz_policies(client_id: str):
    return keycloak.get_client_authz_policies(client_id)


@router.post("/client")
def create_client_policy(client_id: str, client_policy: ClientPermission):
    client_policy = client_policy.model_dump()
    client_policy["type"] = "client"
    return keycloak.register_client_policy(client_id, client_policy)


@router.post("/aggregated")
def create_aggregated_policy(client_id: str, aggregated_policy: AggregatedPermission):
    aggregated_policy = aggregated_policy.model_dump()
    aggregated_policy["type"] = "aggregated"
    return keycloak.register_aggregated_policy(client_id, aggregated_policy)


@router.post("/scope")
def create_client_scope_policy(client_id: str, scope_policy: ScopePermission):
    scope_policy = scope_policy.model_dump()
    scope_policy["type"] = "scope"
    return keycloak.register_client_scope_policy(client_id, scope_policy)


@router.post("/group")
def create_group_policy(client_id: str, group_policy: GroupPermission):
    group_policy = group_policy.model_dump()
    group_policy["type"] = "group"
    return keycloak.register_group_policy(client_id, group_policy)


@router.post("/regex")
def create_regex_policy(client_id: str, regex_policy: RegexPermission):
    regex_policy = regex_policy.model_dump()
    regex_policy["type"] = "regex"
    return keycloak.register_regex_policy(client_id, regex_policy)


@router.post("/role")
def create_role_policy(client_id: str, role_policy: RolePermission):
    role_policy = role_policy.model_dump()
    role_policy["type"] = "role"
    return keycloak.register_role_policy(client_id, role_policy)


@router.post("/time")
def create_time_policy(client_id: str,
                       time_policy: RelativeTimePermission | DayMonthTimePermission | MonthTimePermission |
                                    YearTimePermission | HourTimePermission | MinuteTimePermission):
    time_policy = time_policy.model_dump()
    time_policy["type"] = "time"
    return keycloak.register_time_policy(client_id, time_policy)


@router.post("/user")
def create_user_policy(client_id: str, user_policy: UserPermission):
    user_policy = user_policy.model_dump()
    user_policy["type"] = "user"
    return keycloak.register_user_policy(client_id, user_policy)


@router.put("/{policy_id}")
def update_policy(client_id: str, policy_id: str,
                  policy: ModifyClientPermission | ModifyAggregatedPermission | ModifyScopePermission |
                          ModifyRegexPermission | ModifyRolePermission | ModifyRelativeTimePermission | ModifyDayMonthTimePermission |
                          ModifyMonthTimePermission | ModifyYearTimePermission | ModifyHourTimePermission | ModifyMinuteTimePermission |
                          ModifyUserPermission):
    return keycloak.update_policy(client_id, policy_id, policy.model_dump())


@router.delete("/{policy_id}")
def delete_policy(client_id: str, policy_id: str):
    return keycloak.delete_policy(client_id, policy_id)