import os
from typing import Mapping

from identityutils.configuration import load_configuration

config: Mapping[str, str] = (
    load_configuration(os.path.join(os.path.dirname(__file__), "../config.ini"))
)