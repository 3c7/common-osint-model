from abc import ABC
from logging import getLogger, basicConfig
from typing import Dict, List, Union

basicConfig(level="INFO")


class Logger(ABC):
    """Abstract class which implements just an info method printing a message to stdout via Logger class."""

    @classmethod
    def info(cls, message: str):
        logger = getLogger(cls.__name__)
        logger.info(message)

    @classmethod
    def debug(cls, message: str):
        logger = getLogger(cls.__name__)
        logger.debug(message)

    @classmethod
    def warning(cls, message: str):
        logger = getLogger(cls.__name__)
        logger.warning(message)

    @classmethod
    def error(cls, message: str):
        logger = getLogger(cls.__name__)
        logger.error(message)


class ShodanDataHandler(ABC):
    """Abstract base class indicating that a class implements from_shodan()."""

    @classmethod
    def from_shodan(cls, d: Dict):
        pass


class CensysDataHandler(ABC):
    """Abstract base class indicating that a class implements from_censys()."""

    @classmethod
    def from_censys(cls, d: Dict):
        pass


class BinaryEdgeDataHandler(ABC):
    """Abstract base class indicating that a class implements from_binaryedge()."""

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        pass
