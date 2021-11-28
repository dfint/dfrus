import logging
import sys
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from typing import Iterable


@lru_cache()
def get_logger() -> logging.Logger:
    log = logging.getLogger(name="dfrus")
    log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.addHandler(create_rotating_file_handler("dfrus.log"))
    return log


def create_rotating_file_handler(filename) -> RotatingFileHandler:
    file_handler = RotatingFileHandler(filename, maxBytes=1024**2, backupCount=0, encoding="utf-8")

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] (%(filename)s).%(funcName)s(%(lineno)d): "
                                  "%(message)s")

    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    file_handler.addFilter(lambda record: record.levelno != logging.INFO)

    return file_handler


def create_stdout_handler(stdout, debug: bool) -> logging.StreamHandler:
    stdout_stream_handler = logging.StreamHandler(stdout)
    stdout_stream_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    return stdout_stream_handler


def create_separate_stream_handlers(stdout, stderr, debug: bool) -> Iterable[logging.StreamHandler]:
    """
    Create two separate logging handlers, one for errors (level ERROR or CRITICAL), one for all other levels
    """
    stdout_stream_handler = create_stdout_handler(stdout, debug)

    def no_error(record: logging.LogRecord):
        return record.levelno < logging.ERROR

    stdout_stream_handler.addFilter(no_error)

    stderr_stream_handler = logging.StreamHandler(stderr)
    stderr_stream_handler.setLevel(logging.ERROR)

    return [stdout_stream_handler, stderr_stream_handler]


def create_stream_handlers(stdout, stderr, debug: bool) -> Iterable[logging.StreamHandler]:
    if not stderr:
        if stdout:
            return [create_stdout_handler(stdout, debug)]
    else:
        return create_separate_stream_handlers(stdout, stderr, debug)

    return []


def init_logger(stdout, stderr, debug: bool) -> logging.Logger:
    log = get_logger()

    for handler in create_stream_handlers(stdout, stderr, debug):
        log.addHandler(handler)

    return log
