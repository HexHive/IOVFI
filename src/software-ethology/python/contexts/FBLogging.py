import logging

import sys

LOGGER_NAME = "fb-logger"
logger = logging.getLogger(LOGGER_NAME)
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)
