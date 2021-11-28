import logging
import sys
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from typing import Iterable


@lru_cache()
def get_logger() -> logging.Logger:
    log = logging.getLogger(name="dfrus")
    log.setLevel(logging.INFO)
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.addHandler(create_rotating_file_handler("dfrus.log"))
    return log


def create_rotating_file_handler(filename) -> RotatingFileHandler:
    file_handler = RotatingFileHandler(filename, maxBytes=1024**2, backupCount=0, encoding="utf-8")

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] (%(filename)s).%(funcName)s(%(lineno)d): "
                                  "%(message)s")

    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.WARNING)
    return file_handler


def create_separate_stream_handlers(stdout, stderr) -> Iterable[logging.StreamHandler]:
    """
    Create two separate logging handlers, one for errors (level ERROR or CRITICAL), one for all other levels
    """
    stdout_stream = logging.StreamHandler(stdout)

    def no_error(record: logging.LogRecord):
        return record.levelno < logging.ERROR

    stdout_stream.addFilter(no_error)
    stderr_stream = logging.StreamHandler(stderr)
    stderr_stream.setLevel(logging.ERROR)
    return [stdout_stream, stderr_stream]


def create_stream_handlers(stdout, stderr) -> Iterable[logging.StreamHandler]:
    if not stderr:
        if stdout:
            return [logging.StreamHandler(stdout)]
    else:
        return create_separate_stream_handlers(stdout, stderr)

    return []


def init_logger(stdout, stderr) -> logging.Logger:
    log = get_logger()

    for handler in create_stream_handlers(stdout, stderr):
        log.addHandler(handler)

    return log
