import logging
import os

from fastapi import APIRouter

from app.keycloak_client import keycloak
from app.log import log
from app.models.clients import Client
from app.routers.clients_resources import register_resources

router = APIRouter(
    prefix="/clients",
    tags=["Clients"]
)


@router.post("")
def create_client(client: Client):
    resources = client.resources
    client_dict = client.model_dump()
    del client_dict['resources']
    response_client = keycloak.create_client(client_dict)
    if resources:
        response_resources = register_resources(client.clientId, resources)
        return {
            "client": response_client,
            "resources": response_resources
        }
    return {
        "client": response_client
    }


# def _validate_register_resource(resources: Resources):
#     payload_minimum_example = """
#         payload example ->
#             [{
#                 "resource":{
#                     "name": "resource1",
#                     "uris": ["/resource1/", "/resource2/"]
#                 },
#                 "permissions": {
#                     "user": ["user1","user2"],
#                 }
#             }]
#         """
#     time_options = """time must be a dictionary with one of:
#                                "notAfter":"1970-01-01 00:00:00"
#                                "notBefore":"1970-01-01 00:00:00"
#                                "dayMonth":<day-of-month>
#                                "dayMonthEnd":<day-of-month>
#                                "month":<month>
#                                "monthEnd":<month>
#                                "year":<year>
#                                "yearEnd":<year>
#                                "hour":<hour>
#                                "hourEnd":<hour>
#                                "minute":<minute>
#                                "minuteEnd":<minute>"""
#
#     policy_types = ['user', 'client', 'role', 'time', 'regex', 'group', 'scope', 'aggregated']
#     resource_accepted_fields = ['name', 'uris', 'attributes', 'ownerManagedAccess', 'resource_scopes', 'type']
#     policy_accepted_fields = ['logic', 'decisionStrategy', 'name', 'description', 'groupsClaim', 'targetClaim']
#     time_accepted_fields = ["notAfter", "notBefore", "dayMonth", "dayMonthEnd", "month", "monthEnd", "year", "yearEnd",
#                             "hour", "hourEnd", "minute", "minuteEnd"]
#     if 'resource' not in resources:
#         return 'Resource field required. ' + payload_minimum_example
#     if 'permissions' not in resources or resources['permissions'] == {}:
#         return 'Permissions field required. ' + payload_minimum_example
#     if 'name' not in resources['resource']:
#         return 'Resource name required. ' + payload_minimum_example
#     if 'uris' not in resources['resource']:
#         return 'Resource uris required. ' + payload_minimum_example
#     for resource_key in resources['resource']:
#         if resource_key in resource_accepted_fields:
#             continue
#         else:
#             return 'There are fields not accepted in "resource"'
#
#     for key in resources['permissions']:
#         if not isinstance(resources['permissions'][key], list) and not isinstance(
#                 resources['permissions'][key], dict):
#             return "The value of {} ".format(key) + "must be a list of strings or a dictionary"
#         if key not in policy_types:
#             return 'Permissions type not found. Needs to be one of the following: ' + ', '.join(policy_types)
#         if key == 'time':
#             if not isinstance(resources['permissions']['time'], dict):
#                 return time_options
#             for time_key in resources['permissions']['time']:
#                 if time_key in time_accepted_fields or time_key in policy_accepted_fields:
#                     continue
#                 else:
#                     return 'There are fields not accepted or ' + time_options
#         if key == 'regex':
#             if not isinstance(resources['permissions'][key], dict):
#                 return 'Regex must be a dictionary like {"pattern":<regex>}'
#             for regex_key in resources['permissions'][key]:
#                 if regex_key == 'pattern' or regex_key in policy_accepted_fields:
#                     continue
#                 else:
#                     return 'The field "pattern" is not in the regex dictionary or there are fields not accepted'
#         if key == 'user':
#             if not isinstance(resources['permissions'][key], list):
#                 for user_key in resources['permissions'][key]:
#                     if user_key == 'users' or user_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'The field "users" is not in the user dictionary or there are fields not accepted'
#         if key == 'role':
#             if not isinstance(resources['permissions'][key], list):
#                 for role_key in resources['permissions'][key]:
#                     if role_key == 'roles' or role_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'The field "roles" is not in the role dictionary or there are fields not accepted'
#         if key == 'group':
#             if not isinstance(resources['permissions'][key], list):
#                 for group_key in resources['permissions'][key]:
#                     if group_key == 'groups' or group_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'The field "groups" is not in the group dictionary or there are fields not accepted'
#         if key == 'client-scope':
#             if not isinstance(resources['permissions'][key], list):
#                 for client_scope_key in resources['permissions'][key]:
#                     if client_scope_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'There are fields not accepted'
#
#         if key == 'aggregated':
#             if not isinstance(resources['permissions'][key], list):
#                 for aggregated_key in resources['permissions'][key]:
#                     if aggregated_key == 'policies' or aggregated_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'The field "policies" is not in the aggregated dictionary or there are fields not accepted'
#
#         if key == 'client':
#             if not isinstance(resources['permissions'][key], list):
#                 for client_key in resources['permissions'][key]:
#                     if client_key in policy_accepted_fields:
#                         continue
#                     else:
#                         return 'There are fields not accepted'
#
#     return None