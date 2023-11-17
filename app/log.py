import logging
from logging.config import dictConfig

from app.configuration import get_settings

settings = get_settings()
logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s | %(asctime)s | %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",

        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "um-identity-api": {"handlers": ["default"], "level": settings.log_level.upper()},
    },
}
dictConfig(logging_config)
logger = logging.getLogger("um-identity-api")