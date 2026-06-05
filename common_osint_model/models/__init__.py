from abc import ABC


class ShodanDataHandler(ABC):
    """Abstract base class indicating that a class implements from_shodan()."""

    @classmethod
    def from_shodan(cls, *args, **kwargs):
        pass


class CensysDataHandler(ABC):
    """Abstract base class indicating that a class implements from_censys()."""

    @classmethod
    def from_censys(cls, *args, **kwargs):
        pass


class BinaryEdgeDataHandler(ABC):
    """Abstract base class indicating that a class implements from_binaryedge()."""

    @classmethod
    def from_binaryedge(cls, *args, **kwargs):
        pass
