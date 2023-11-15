from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.models.clients import ClientPolicy, AggregatedPolicy, \
    ScopePolicy, GroupPolicy, RegexPolicy, RolePolicy, RelativeTimePolicy, YearTimePolicy, HourTimePolicy, \
    DayMonthTimePolicy, MonthTimePolicy, MinuteTimePolicy, UserPolicy, ModifyClientPolicy, ModifyRegexPolicy, \
    ModifyMonthTimePolicy, ModifyUserPolicy, ModifyAggregatedPolicy, ModifyRolePolicy, ModifyYearTimePolicy, \
    ModifyRelativeTimePolicy, ModifyScopePolicy, ModifyHourTimePolicy, ModifyDayMonthTimePolicy, ModifyMinuteTimePolicy

router = APIRouter(
    prefix="/{client_id}/policies",
    tags=["Clients Policies"],
)


@router.get("")
def get_client_authz_policies(client_id: str):
    return keycloak.get_client_authz_policies(client_id)


@router.post("/client")
def create_client_policy(client_id: str, client_policy: ClientPolicy):
    client_policy["type"] = "client"
    return keycloak.register_client_policy(client_policy, client_id)


@router.post("/aggregated")
def create_aggregated_policy(client_id: str, aggregated_policy: AggregatedPolicy):
    aggregated_policy["type"] = "aggregated"
    return keycloak.register_aggregated_policy(aggregated_policy, client_id)


@router.post("/scope")
def create_client_scope_policy(client_id: str, scope_policy: ScopePolicy):
    scope_policy["type"] = "scope"
    return keycloak.register_client_scope_policy(scope_policy, client_id)


@router.post("/group")
def create_group_policy(client_id: str, group_policy: GroupPolicy):
    group_policy["type"] = "group"
    return keycloak.register_group_policy(group_policy, client_id)


@router.post("/regex")
def create_regex_policy(client_id: str, regex_policy: RegexPolicy):
    regex_policy["type"] = "regex"
    return keycloak.register_regex_policy(regex_policy, client_id)


@router.post("/role")
def create_role_policy(client_id: str, role_policy: RolePolicy):
    role_policy["type"] = "role"
    return keycloak.register_role_policy(role_policy, client_id)


@router.post("/time")
def create_time_policy(client_id: str,
                       time_policy: RelativeTimePolicy | DayMonthTimePolicy | MonthTimePolicy |
                                    YearTimePolicy | HourTimePolicy | MinuteTimePolicy):
    time_policy["type"] = "time"
    return keycloak.register_time_policy(time_policy, client_id)


@router.post("/user")
def create_user_policy(client_id: str, user_policy: UserPolicy):
    return keycloak.register_user_policy(user_policy, client_id)


@router.put("/{policy_id}")
def update_policy(client_id: str, policy_id: str,
                  policy: ModifyClientPolicy | ModifyAggregatedPolicy | ModifyScopePolicy |
                          ModifyRegexPolicy | ModifyRolePolicy | ModifyRelativeTimePolicy | ModifyDayMonthTimePolicy |
                          ModifyMonthTimePolicy | ModifyYearTimePolicy | ModifyHourTimePolicy | ModifyMinuteTimePolicy |
                          ModifyUserPolicy):
    return keycloak.update_policy(client_id, policy_id, policy)


@router.delete("/{policy_id}")
def delete_policy(client_id: str, policy_id: str):
    return keycloak.delete_policy(policy_id, client_id)