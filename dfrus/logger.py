import logging
from logging.handlers import RotatingFileHandler
from functools import lru_cache


@lru_cache()
def get_logger() -> logging.Logger:
    logger = logging.Logger(name="dfrus")

    file_handler = RotatingFileHandler("dfrus.log", maxBytes=1024**2, backupCount=1, encoding="utf-8")

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s "
                                  "(%(filename)s).%(funcName)s(%(lineno)d): %(message)s")

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_stream_handler(stream) -> logging.StreamHandler:
    return logging.StreamHandler(stream)
