from identityutils.keycloak_client import KeycloakClient
from keycloak import KeycloakConnectionError
from retry.api import retry_call
from urllib3.exceptions import NewConnectionError

from app.configuration import get_settings
from app.log import logger

settings = get_settings()

def __create_keycloak_client():
    logger.info("Starting Keycloak client for: " + settings.auth_server_url + "/realms/" + settings.realm)
    return KeycloakClient(
        server_url=settings.auth_server_url,
        realm=settings.realm,
        username=settings.admin_username,
        password=settings.admin_password,
    )


keycloak = retry_call(
    __create_keycloak_client,
    exceptions=(KeycloakConnectionError, NewConnectionError),
    delay=0.5,
    backoff=1.2,
    jitter=(1, 2),
    logger=logger
)