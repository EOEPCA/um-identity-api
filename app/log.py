import logging

from app.configuration import config


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


logger = logging.getLogger('um-identity-api')
logging_level = get_logging_level()
logger.setLevel(logging_level)
fh = logging.FileHandler('um-identity-api.log')
fh.setLevel(logging_level)
logger.addHandler(fh)