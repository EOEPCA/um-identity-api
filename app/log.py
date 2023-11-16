import logging

# create logger with 'spam_application'
logger = logging.getLogger('um-identity-api')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('um-identity-api.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)