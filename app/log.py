import logging

from logging.config import dictConfig

from app.configuration import get_settings

settings = get_settings()
print(settings)
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

# logging_config = {
#     "logger_name": "um-identity-api",
#     "logger_format": "%(levelprefix)s | %(asctime)s | %(message)s",
#     "log_level": "info",
#     "disable_existing_loggers": False,
#     "version": 1,
#     "formatters": {
#         "default": {
#             "()": "uvicorn.logging.DefaultFormatter",
#             "fmt": settings.logger_format,
#             "datefmt": "%Y-%m-%d %H:%M:%S",
#         },
#     },
#     "handlers": {
#         "default": {
#             "formatter": "default",
#             "class": "logging.StreamHandler",
#             "stream": "ext://sys.stderr",
#         },
#     },
#     "loggers": {
#         settings.logger_name: {"handlers": ["default"], "level": settings.log_level.upper()},
#     }
# }

dictConfig(logging_config)
logger = logging.getLogger("um-identity-api")