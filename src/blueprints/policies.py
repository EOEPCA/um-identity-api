from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    policies = Blueprint('policies', __name__)

    # -------- Always returns empty -------
    #@policies.route("/policies", methods=["GET"])
    #def get_policies():
    #    resource = request.args.get('resource', "")
    #    name = request.args.get('name', "")
    #    scope = request.args.get('uri', "")
    #    first = int(request.args.get('first', 0))
    #    maximum = int(request.args.get('maximum', -1))
    #    return keycloak_client.get_policies(resource, name, scope, first, maximum)
    # --------------- GET -----------------
    
    @policies.route("/<client_id>/policies", methods=["GET"])
    def get_client_authz_policies(client_id: str):
        return keycloak_client.get_client_authz_policies(client_id)

    # --------------- POST -----------------

    @policies.route("/<client_id>/policies/client", methods=["POST"])
    def create_client_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_client_policy(policy, client_id)
    
    
    @policies.route("/<client_id>/policies/aggregated", methods = ["POST"])
    def create_aggregated_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_aggregated_policy(policy, client_id)
        
    @policies.route("/<client_id>/policies/scope", methods = ["POST"])
    def create_client_scope_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_client_scope_policy(policy, client_id)

    @policies.route("/<client_id>/policies/group", methods = ["POST"])
    def create_group_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_group_policy(policy, client_id)

    @policies.route("/<client_id>/policies/regex", methods = ["POST"])
    def create_regex_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_regex_policy(policy, client_id)
    
    @policies.route("/<client_id>/policies/role", methods = ["POST"])
    def create_role_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_role_policy(policy, client_id)
    
    @policies.route("/<client_id>/policies/time", methods = ["POST"])
    def create_time_policy(client_id: str):
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
        policy = request.get_json()
        return keycloak_client.register_time_policy(policy, client_id)
    
    @policies.route("/<client_id>/policies/user", methods = ["POST"])
    def create_user_policy(client_id: str):
        policy = request.get_json()
        return keycloak_client.register_user_policy(policy, client_id)

    
    
    # --------------- UPDATE -----------------
    
    @policies.route("/<client_id>/policies/<policy_id>", methods=["PUT"])
    def update_policy(client_id: str, policy_id: str):
        policy = request.get_json()
        return keycloak_client.update_policy(policy_id, policy, client_id)
    
    # --------------- DELETE -----------------

    @policies.route("/<client_id>/policies/<policy_id>", methods=["DELETE"])
    def delete_policy(client_id: str ,policy_id: str):
        return keycloak_client.delete_policy(policy_id, client_id)


    return policies
