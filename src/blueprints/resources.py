from flask import Blueprint, request
from keycloak import KeycloakDeleteError, KeycloakGetError, KeycloakPostError, KeycloakPutError


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    resources = Blueprint('resources', __name__)

    @resources.route("/<client_id>/resources", methods=["GET"])
    def get_resources(client_id: str):
        try:
            response =  keycloak_client.get_resources(client_id)
            return response
        except KeycloakGetError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/resources/<resource_id>", methods=["GET"])
    def get_resource(resource_id: str):
        try:
            response =  keycloak_client.get_resource(resource_id)
            return response
        except KeycloakGetError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources", methods=["POST"])
    def register_resource(client_id: str ):
        resource = request.get_json()
        try:
            response =  keycloak_client.register_resource(resource, client_id)
            return response
        except KeycloakPostError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)
        

    @resources.route("/<client_id>/register-resources", methods=["POST"])
    def register_and_protect_resources(client_id: str ):
        """payload = [{
            "resource":{
                "name": "resource1",
                "uris": ["/resource1/", "/resource2/"],
                'attributes': {},
                'scopes': ['view'],
                'ownerManagedAccess': False,
            },
            "permissions": {
                "user": {
                    "users":["user1","user2"],
                    "logic":"NEGATIVE"
                    },
                "role": {
                    "roles":["role1","role2"],
                    "logic":"POSITIVE"
                    },
            },
            "decisionStrategy": "UNANIMOUS"
        }]"""
        payload = request.get_json()
        policy_list = []
        
        for item in payload:
            # validate item fields
            error = _validate_register_resource(item)
            if error:
                return custom_error(error, 400)
            
            resource = item["resource"]
            policies = item["permissions"]
            decisionStrategy = item['decisionStrategy'] if 'decisionStrategy' in item else "UNANIMOUS"
            type = 'urn:' + client_id + ':resources:default'
            scopes = resource['scopes'] if 'scopes' in resource and resource['scopes'] != [] else ['access']

            try:
                # reconstruct resource object so it works when user sends unknown fields and to change field names to match what keycloak api expects
                response_resource = keycloak_client.register_resource( resource, client_id)
                for policy_type in policies:
                    policy = {"name": resource["name"].replace(" ", "") + "_" + policy_type + "_policy"}
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
                    response_policy = keycloak_client.register_general_policy(policy, client_id, policy_type)

                permission_payload = {
                    "type": "resource",
                    "name": resource["name"] + "permission",
                    "decisionStrategy": decisionStrategy,
                    "resources": [
                        resource["name"]
                    ],
                    "policies": policy_list
                }

                permission_response = keycloak_client.create_client_authz_resource_based_permission(client_id, permission_payload)

                return response_resource
            except KeycloakPostError as error:
                return custom_error(error.error_message, error.response_code)
            except:
                return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["PUT"])
    def update_resource(client_id: str, resource_id: str):
        resource = request.get_json()
        try:
            response =  keycloak_client.update_resource(resource_id, resource, client_id)
            return response
        except KeycloakPutError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    @resources.route("/<client_id>/resources/<resource_id>", methods=["DELETE"])
    def delete_resource(client_id: str, resource_id: str):
        try:
            response =  keycloak_client.delete_resource(resource_id, client_id)
            return response
        except KeycloakDeleteError as error:
            return custom_error(error.error_message, error.response_code)
        except:
            return custom_error("Unknown server error", 500)

    def custom_error(message, status_code): 
        return message, status_code
    
    def _validate_register_resource(item):
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
        resource_accepted_fields = ['name','uris','attributes', 'ownerManagedAccess', 'resource_scopes', 'type']
        policy_accepted_fields = ['logic', 'decisionStrategy', 'name', 'description', 'groupsClaim', 'targetClaim']
        time_accepted_fields = ["notAfter","notBefore","dayMonth","dayMonthEnd","month","monthEnd","year","yearEnd","hour","hourEnd","minute","minuteEnd"]
        if 'resource' not in item:
            return 'Resource field required. ' + payload_minimum_example
        if 'permissions' not in item or item['permissions'] == {}:
            return 'Permissions field required. ' + payload_minimum_example
        if 'name' not in item['resource']:
            return 'Resource name required. '+ payload_minimum_example
        if 'uris' not in item['resource']:
            return 'Resource uris required. '+ payload_minimum_example
        for resource_key in item['resource']:
            if resource_key in resource_accepted_fields:
                continue
            else:
                return 'There are fields not accepted in "resource"'
        
        for key in item['permissions']:
            if not isinstance(item['permissions'][key], list) and not isinstance(item['permissions'][key], dict):
                return "The value of {} ".format(key) + "must be a list of strings or a dictionary"
            if key not in policy_types:
                return 'Permissions type not found. Needs to be one of the following: ' + ', '.join(policy_types)
            if key == 'time':
                if not isinstance(item['permissions']['time'], dict):
                    return time_options
                for time_key in item['permissions']['time']:
                    if time_key in time_accepted_fields or time_key in policy_accepted_fields:
                        continue
                    else:
                        return 'There are fields not accepted or ' + time_options
            if key == 'regex':
                if not isinstance(item['permissions'][key], dict):
                    return 'Regex must be a dictionary like {"pattern":<regex>}'
                for regex_key in item['permissions'][key]:
                    if regex_key == 'pattern' or regex_key in policy_accepted_fields:
                        continue
                    else:
                        return 'The field "pattern" is not in the regex dictionary or there are fields not accepted'
            if key == 'user':
                if not isinstance(item['permissions'][key], list):
                    for user_key in item['permissions'][key]:
                        if user_key == 'users' or user_key in policy_accepted_fields:
                            continue
                        else:
                            return 'The field "users" is not in the user dictionary or there are fields not accepted'
            if key == 'role':
                if not isinstance(item['permissions'][key], list):
                    for role_key in item['permissions'][key]:
                        if role_key == 'roles' or role_key in policy_accepted_fields:
                            continue
                        else:
                            return 'The field "roles" is not in the role dictionary or there are fields not accepted'
            if key == 'group':
                if not isinstance(item['permissions'][key], list):
                    for group_key in item['permissions'][key]:
                        if group_key == 'groups' or group_key in policy_accepted_fields:
                            continue
                        else:
                            return 'The field "groups" is not in the group dictionary or there are fields not accepted'
            if key == 'client-scope':
                if not isinstance(item['permissions'][key], list):
                    for client_scope_key in item['permissions'][key]:
                        if client_scope_key in policy_accepted_fields:
                            continue
                        else:
                            return 'There are fields not accepted'
                        
            if key == 'aggregated':
                if not isinstance(item['permissions'][key], list):
                    for aggregated_key in item['permissions'][key]:
                        if aggregated_key == 'policies' or aggregated_key in policy_accepted_fields:
                            continue
                        else:
                            return 'The field "policies" is not in the aggregated dictionary or there are fields not accepted'
            
            if key == 'client':
                if not isinstance(item['permissions'][key], list):
                    for client_key in item['permissions'][key]:
                        if client_key in policy_accepted_fields:
                            continue
                        else:
                            return 'There are fields not accepted'   
                        
        return None

    return resources
