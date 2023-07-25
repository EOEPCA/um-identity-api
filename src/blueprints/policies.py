from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    policies = Blueprint('policies', __name__)


    @policies.route("/policies", methods=["GET"])
    def get_policies():
        resource = request.args.get('resource', "")
        name = request.args.get('name', "")
        scope = request.args.get('uri', "")
        first = int(request.args.get('first', 0))
        maximum = int(request.args.get('maximum', -1))
        return keycloak_client.get_policies(resource, name, scope, first, maximum)
    # --------------- GET -----------------
    @policies.route("/policies/<client_id>", methods=["GET"])
    def get_client_authz_policies(client_id: str):
        return keycloak_client.get_client_authz_policies(client_id)

    # --------------- POST -----------------

    @policies.route("/policies/client", methods=["POST"])
    def create_client_policy():
        policy = request.get_json()
        return keycloak_client.register_client_policy(policy)
    
    
    @policies.route("/policies/aggregated", methods = ["POST"])
    def create_aggregated_policy():
        payload = request.get_json()
        name = payload["name"]
        policies = payload["policies"]
        strategy = payload["strategy"]
        return keycloak_client.register_aggregated_policy(name, policies, strategy)
        
    @policies.route("/policies/scope", methods = ["POST"])
    def create_client_scope_policy():
        policy = request.get_json()
        return keycloak_client.register_client_scope_policy(policy)

    @policies.route("/policies/group", methods = ["POST"])
    def create_group_policy():
        name = request.get_json()["name"]
        groups = request.get_json()["groups"]
        groups_claim = request.get_json()["groups_claim"]
        return keycloak_client.register_group_policy(name, groups, groups_claim)

    @policies.route("/policies/regex", methods = ["POST"])
    def create_regex_policy():
        payload = request.get_json()
        name = payload["name"]
        regex = payload["regex"]
        target_claim = payload["target_claim"]
        return keycloak_client.register_regex_policy(name, regex, target_claim)
    
    @policies.route("/policies/role", methods = ["POST"])
    def create_role_policy():
        payload = request.get_json()
        name = payload["name"]
        roles = payload["roles"]
        return keycloak_client.register_role_policy(name, roles)
    
    @policies.route("/policies/time", methods = ["POST"])
    def create_time_policy():
        # time can be one of:
        # "notAfter":"1970-01-01 00:00:00"
        # "notBefore":"1970-01-01 00:00:00"
        # "dayMonth":<day-of-month>
        # "dayMonthEnd":<day-of-month>
        # "month":<month>
        # "monthEnd":<month>
        # "year":<year>
        # "yearEnd":<year>
        # "hour":<hour>
        # "hourEnd":<hour>
        # "minute":<minute>
        # "minuteEnd":<minute>
        possible_times = [
            "notAfter",
            "notBefore",
            "dayMonth",
            "dayMonthEnd",
            "month",
            "monthEnd",
            "year",
            "yearEnd",
            "hour",
            "hourEnd",
            "minute",
            "minuteEnd"
        ]
        payload = request.get_json()
        name = payload["name"]
        time = {}
        for key, value in payload.items():
            if key in possible_times:
                time[key] = value
        return keycloak_client.register_time_policy(name, time)
    
    @policies.route("/policies/user", methods = ["POST"])
    def create_user_policy():
        payload = request.get_json()
        name = payload["name"]
        users = payload["users"]
        return keycloak_client.register_user_policy(name, users)

    
    
    # --------------- UPDATE -----------------
    
    @policies.route("/policies/<policy_id>", methods=["PUT"])
    def update_policy(policy_id: str):
        policy = request.get_json()
        return keycloak_client.update_policy(policy_id, policy)
    
    # --------------- DELETE -----------------

    @policies.route("/policies/<policy_id>", methods=["DELETE"])
    def delete_policy(policy_id: str):
        return keycloak_client.delete_policy(policy_id)


    return policies
