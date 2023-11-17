from functools import lru_cache
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    # Keycloak
    auth_server_url: str = "http://localhost"
    admin_username: str = "admin"
    admin_password: str = "admin"
    realm: str = "master"

    # Swagger
    version: str = "v1.0.0"

    # Logging
    log_level: str = "INFO"


@lru_cache
def get_settings():
    return Settings()