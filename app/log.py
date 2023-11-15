import logging
import os

import identityutils.logger as logger

logger.Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../logging.yaml"))
log = logging.getLogger("IDENTITY_API")