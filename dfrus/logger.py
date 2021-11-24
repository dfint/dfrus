import logging
import sys
from functools import lru_cache
from logging.handlers import RotatingFileHandler


@lru_cache()
def logger() -> logging.Logger:
    log = logging.getLogger(name="dfrus")
    log.setLevel(logging.INFO)

    file_handler = RotatingFileHandler("dfrus.log", maxBytes=1024**2, backupCount=1, encoding="utf-8")

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] (%(filename)s).%(funcName)s(%(lineno)d): "
                                  "%(message)s")

    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)

    return log


def create_stream_handler(stream) -> logging.StreamHandler:
    if stream:
        return logging.StreamHandler(stream)
    else:
        return logging.StreamHandler(sys.stdout)
