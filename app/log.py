import logging

from logging.config import dictConfig
from pydantic import BaseModel

from app.configuration import config



class LogConfig(BaseModel):
    """Logging configuration to be set for the server"""

    LOGGER_NAME: str = "mycoolapp"
    LOG_FORMAT: str = "%(levelprefix)s | %(asctime)s | %(message)s"
    level = config.get("App", "logging_level")
    if not level:
        level = 'INFO'
    LOG_LEVEL: str = level.upper()

    # Logging config
    version = 1
    disable_existing_loggers = False
    formatters = {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    }
    handlers = {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
    }
    loggers = {
        LOGGER_NAME: {"handlers": ["default"], "level": LOG_LEVEL},
    }

def get_logging_level():
    level = config.get("App", "logging_level")
    if not level:
        level = 'info'
    level = level.lower()
    if level == 'critical' or level == 'critical':
        return logging.CRITICAL
    if level == 'error':
        return logging.ERROR
    if level == 'warning' or level == 'warn':
        return logging.WARNING
    if level == 'info':
        return logging.INFO
    if level == 'debug':
        return logging.DEBUG
    if level == 'notset':
        return logging.NOTSET


dictConfig(LogConfig().model_dump())
logger = logging.getLogger("um-identity-api")