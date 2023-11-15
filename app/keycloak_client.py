import os

from identityutils.configuration import load_configuration
from identityutils.keycloak_client import KeycloakClient
from keycloak import KeycloakConnectionError
from retry.api import retry_call
from urllib3.exceptions import NewConnectionError

from app.log import log


def __create_keycloak_client():
    config_path = os.path.join(os.path.dirname(__file__), "../config.ini")
    config = load_configuration(config_path)
    auth_server_url = config.get("Keycloak", "auth_server_url")
    realm = config.get("Keycloak", "realm")
    log.info("Starting Keycloak client for: " + auth_server_url + "/realms/" + realm)
    return KeycloakClient(
        server_url=auth_server_url,
        realm=realm,
        username=config.get("Keycloak", "admin_username"),
        password=config.get("Keycloak", "admin_password")
    )


keycloak = retry_call(
    __create_keycloak_client,
    exceptions=(KeycloakConnectionError, NewConnectionError),
    delay=0.5,
    backoff=1.2,
    jitter=(1, 2),
    logger=log
)