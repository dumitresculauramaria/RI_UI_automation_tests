import importlib
import logging
import os
import time

test_reports = importlib.import_module("test-reports")

loggers = {}


def logger() -> object:
    global loggers
    prefix = ' Test Run'

    if prefix in loggers:
        key = list(loggers.keys())[0]
        logger = loggers.get(key)
    else:
        logger = createLogger(prefix, loggers)

    return logger


def createLogger(prefix, loggers):
    __logsFolder = os.path.dirname(test_reports.__file__)

    timestamp = time.strftime('%d %b %Y %H')

    name = prefix + ' ' + timestamp + '.log'
    path = os.path.join(__logsFolder, name)

    logger = logging.getLogger(prefix)
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(path)
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)8s\t - \t%(funcName)30s - \t%(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    loggers[prefix] = logger

    return logger
