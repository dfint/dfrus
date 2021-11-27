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
    file_handler = RotatingFileHandler(filename, maxBytes=1024**2, backupCount=1, encoding="utf-8")

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] (%(filename)s).%(funcName)s(%(lineno)d): "
                                  "%(message)s")

    file_handler.setFormatter(formatter)
    return file_handler


def create_separate_stream_handlers(stdout, stderr) -> Iterable[logging.StreamHandler]:
    """
    Create two separate logging handlers, one for errors (level ERROR or CRITICAL), one for all other levels
    """
    stdout_stream = logging.StreamHandler(stdout)
    stdout_stream.addFilter(lambda record: record.level < logging.ERROR)
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


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    get_logger().error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


def init_logger(stdout, stderr) -> logging.Logger:
    log = get_logger()

    for handler in create_stream_handlers(stdout, stderr):
        log.addHandler(handler)

    sys.excepthook = handle_exception

    return log
