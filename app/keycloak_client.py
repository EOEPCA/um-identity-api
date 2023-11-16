from identityutils.keycloak_client import KeycloakClient
from keycloak import KeycloakConnectionError
from retry.api import retry_call
from urllib3.exceptions import NewConnectionError

from app.configuration import config
from app.log import logger


def __create_keycloak_client():
    auth_server_url = config.get("Keycloak", "auth_server_url")
    realm = config.get("Keycloak", "realm")
    logger.info("Starting Keycloak client for: " + auth_server_url + "/realms/" + realm)
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
    logger=logger
)