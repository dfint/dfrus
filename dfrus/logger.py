import logging
from logging.handlers import RotatingFileHandler
from functools import lru_cache


@lru_cache()
def get_logger() -> logging.Logger:
    logger = logging.Logger(name="dfrus")

    file_handler = RotatingFileHandler("dfrus.log", maxBytes=1024**2, backupCount=1, encoding="utf-8")
    logger.addHandler(file_handler)

    return logger
