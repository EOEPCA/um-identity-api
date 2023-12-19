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
def create_client_policy(client_id: str, policy: ClientPermission):
    policy = policy.model_dump()
    policy["type"] = "client"
    return keycloak.register_client_policy(client_id, policy)


@router.post("/aggregated")
def create_aggregated_policy(client_id: str, policy: AggregatedPermission):
    policy = policy.model_dump()
    policy["type"] = "aggregated"
    return keycloak.register_aggregated_policy(client_id, policy)


@router.post("/scope")
def create_client_scope_policy(client_id: str, policy: ScopePermission):
    policy = policy.model_dump()
    policy["type"] = "scope"
    return keycloak.register_client_scope_policy(client_id, policy)


@router.post("/group")
def create_group_policy(client_id: str, policy: GroupPermission):
    policy = policy.model_dump()
    policy["type"] = "group"
    return keycloak.register_group_policy(client_id, policy)


@router.post("/regex")
def create_regex_policy(client_id: str, policy: RegexPermission):
    policy = policy.model_dump()
    policy["type"] = "regex"
    return keycloak.register_regex_policy(client_id, policy)


@router.post("/role")
def create_role_policy(client_id: str, policy: RolePermission):
    policy = policy.model_dump()
    policy["type"] = "role"
    return keycloak.register_role_policy(client_id, policy)


@router.post("/time")
def create_time_policy(client_id: str,
                       policy: RelativeTimePermission | DayMonthTimePermission | MonthTimePermission |
                                    YearTimePermission | HourTimePermission | MinuteTimePermission):
    policy = policy.model_dump()
    policy["type"] = "time"
    return keycloak.register_time_policy(client_id, policy)


@router.post("/user")
def create_user_policy(client_id: str, policy: UserPermission):
    policy = policy.model_dump()
    policy["type"] = "user"
    return keycloak.register_user_policy(client_id, policy)


@router.put("/client/{policy_id}")
def update_client_policy(client_id: str, policy_id: str, policy: ClientPermission):
    policy = policy.model_dump()
    policy["type"] = "client"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/aggregated/{policy_id}")
def update_aggregated_policy(client_id: str, policy_id: str, policy: AggregatedPermission):
    policy = policy.model_dump()
    policy["type"] = "aggregated"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/scope/{policy_id}")
def update_client_scope_policy(client_id: str, policy_id: str, policy: ScopePermission):
    scope_policy = policy.model_dump()
    scope_policy["type"] = "scope"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/group/{policy_id}")
def update_group_policy(client_id: str, policy_id: str, policy: GroupPermission):
    group_policy = policy.model_dump()
    group_policy["type"] = "group"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/regex/{policy_id}")
def update_regex_policy(client_id: str, policy_id: str, policy: RegexPermission):
    policy = policy.model_dump()
    policy["type"] = "regex"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/role/{policy_id}")
def update_role_policy(client_id: str, policy_id: str, policy: RolePermission):
    policy = policy.model_dump()
    policy["type"] = "role"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/time/{policy_id}")
def update_time_policy(client_id: str, policy_id: str,
                       policy: RelativeTimePermission | DayMonthTimePermission | MonthTimePermission |
                               YearTimePermission | HourTimePermission | MinuteTimePermission):
    policy = policy.model_dump()
    policy["type"] = "time"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.put("/user/{policy_id}")
def update_user_policy(client_id: str, policy_id: str, policy: UserPermission):
    policy = policy.model_dump()
    policy["type"] = "user"
    return keycloak.update_policy(client_id, policy_id, policy)


@router.delete("/{policy_id}")
def delete_policy(client_id: str, policy_id: str):
    return keycloak.delete_policy(client_id, policy_id)