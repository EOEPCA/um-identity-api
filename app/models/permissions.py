from enum import Enum
from typing import List, Optional

from pydantic import PositiveInt, Field

from app.models.base import APIBaseModel
from app.models.policies import Logic, PolicyType


class DecisionStrategy(Enum):
    AFFIRMATIVE = 'AFFIRMATIVE'
    UNANIMOUS = 'UNANIMOUS'
    CONSENSUS = 'CONSENSUS'


class ClientPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Client policy name")
    clients: List[str] = Field(description="Client policy clients")
    description: Optional[str] = Field(description="Client policy description")


class AggregatedPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Aggregated Policy name")
    policies: List[str] = Field(description="Aggregated Policy policies")
    description: Optional[str] = Field(description="Aggregated Policy description")


class ScopePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Scope policy name")
    scopes: List[str] = Field(description="Scope policy client scopes")
    description: Optional[str] = Field(description="Scope policy description")


class Group(APIBaseModel):
    id: str = Field(description="Group id")
    path: str = Field(description="Group path")


class GroupPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Group policy name")
    groups: List[Group] = Field(description="Group policy groups")
    groupsClaim: Optional[str] = Field(description="Group policy groups claim")
    description: Optional[str] = Field(description="Group policy description")


class RegexPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Regex policy name")
    pattern: str = Field(description="Regex policy regex pattern")
    targetClaim: Optional[str] = Field(description="Regex policy target claim")
    description: Optional[str] = Field(description="Regex policy description")


class Role(APIBaseModel):
    id: str = Field(description="Role id")


class RolePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Role policy name")
    roles: List[Role] = Field(description="Role policy roles")
    description: Optional[str] = Field(description="Role policy description")


class RelativeTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Relative time policy name")
    notAfter: str = Field(description="Relative time policy end date")
    notBefore: str = Field(description="Relative time policy start date")
    description: Optional[str] = Field(description="Relative time policy description")


class DayMonthTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Day month time policy name")
    dayMonth: PositiveInt = Field(description="Day month time policy day month start")
    dayMonthEnd: PositiveInt = Field(description="Day month time policy day month end")
    description: Optional[str] = Field(description="Day month time policy description")


class MonthTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Month time policy name")
    month: PositiveInt = Field(description="Month time policy month start")
    monthEnd: PositiveInt = Field(description="Month time policy month end")
    description: Optional[str] = Field(description="Month time policy description")


class YearTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Year time policy name")
    year: PositiveInt = Field(description="Year time policy year start")
    yearEnd: PositiveInt = Field(description="Year time policy year end")
    description: Optional[str] = Field(description="Year time policy description")


class HourTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Hour time policy name")
    hour: PositiveInt = Field(description="Hour time policy hour start")
    hourEnd: PositiveInt = Field(description="Hour time policy hour end")
    description: Optional[str] = Field(description="Hour time policy description")


class MinuteTimePermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Minute time policy name")
    minute: PositiveInt = Field(description="Minute time policy minute start")
    minuteEnd: PositiveInt = Field(description="Minute time policy minute end")
    description: Optional[str] = Field(description="Minute time policy description")


class UserPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="User policy name")
    users: List[str] = Field(description="User policy users list")


class ModifyClientPermission(ClientPermission):
    type: PolicyType = Field(PolicyType.CLIENT.value, description="Policy type")


class ModifyAggregatedPermission(AggregatedPermission):
    type: PolicyType = Field(PolicyType.AGGREGATE.value, description="Policy type")


class ModifyScopePermission(ScopePermission):
    type: PolicyType = Field(PolicyType.SCOPE.value, description="Policy type")


class ModifyGroupPermission(GroupPermission):
    type: PolicyType = Field(PolicyType.GROUP.value, description="Policy type")


class ModifyRegexPermission(RegexPermission):
    type: PolicyType = Field(PolicyType.REGEX.value, description="Policy type")


class ModifyRolePermission(RolePermission):
    type: PolicyType = Field(PolicyType.ROLE.value, description="Policy type")


class ModifyRelativeTimePermission(RelativeTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyDayMonthTimePermission(DayMonthTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyMonthTimePermission(MonthTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyYearTimePermission(YearTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyHourTimePermission(HourTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyMinuteTimePermission(MinuteTimePermission):
    type: PolicyType = Field(PolicyType.TIME.value, description="Policy type")


class ModifyUserPermission(UserPermission):
    type: PolicyType = Field(PolicyType.USER.value, description="Policy type")


class ResourceBasedPermission(APIBaseModel):
    logic: Optional[Logic] = Field(Logic.POSITIVE, description="Logic to apply, either POSITIVE or NEGATIVE")
    decisionStrategy: Optional[DecisionStrategy] = Field(DecisionStrategy.UNANIMOUS.value,
                                                         description="Decision strategy to decide how to apply permissions")
    name: str = Field(description="Resource based permission name")
    resources: List[str] = Field(description="Resource based permission resources")
    policies: List[str] = Field(description="Resource based permission policies")