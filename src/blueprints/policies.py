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
    @policies.route("/client_policy/<client_id>", methods=["GET"])
    def get_client_authz_policies(client_id: str):
        return keycloak_client.get_client_authz_policies(client_id)

    # --------------- POST -----------------

    @policies.route("/client_policy", methods=["POST"])
    def create_client_policy():
        policy = request.get_json()
        return keycloak_client.register_client_policy(policy)
    
    
    @policies.route("/aggregated_policy", methods = ["POST"])
    def create_aggregated_policy():
        payload = request.get_json()
        name = payload["name"]
        policies = payload["policies"]
        strategy = payload["strategy"]
        return keycloak_client.register_aggregated_policy(name, policies, strategy)
        
    @policies.route("/scope_policy", methods = ["POST"])
    def create_client_scope_policy():
        policy = request.get_json()
        return keycloak_client.register_client_scope_policy(policy)

    @policies.route("/group_policy", methods = ["POST"])
    def create_group_policy():
        name = request.get_json()["name"]
        groups = request.get_json()["groups"]
        groups_claim = request.get_json()["groups_claim"]
        return keycloak_client.register_group_policy(name, groups, groups_claim)

    @policies.route("/regex_policy", methods = ["POST"])
    def create_regex_policy(name, regex, target_claim):
        payload = request.get_json()
        regex = payload["regex"]
        target_claim = payload["target_claim"]
        return keycloak_client.register_regex_policy(name, regex, target_claim)
    
    @policies.route("/role_policy", methods = ["POST"])
    def create_role_policy(name, roles):
        payload = request.get_json()
        name = policy["name"]
        roles = policy["roles"]
        return keycloak_client.register_role_policy(name, roles)
    
    @policies.route("/time_policy", methods = ["POST"])
    def create_time_policy(name, time):
        payload = request.get_json()
        name = payload["name"]
        time = payload["time"]
        return keycloak_client.register_time_policy(name, time)
    
    @policies.route("/user_policy", methods = ["POST"])
    def create_user_policy(name, users):
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
    
    @policies.route("/policies", methods=["DELETE"])
    def delete_policies():
        policies = request.get_json()
        return keycloak_client.delete_policies(policies)

    return policies
