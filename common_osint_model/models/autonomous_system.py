import ipaddress
from typing import Dict, List, Optional

from pydantic import BaseModel, validator

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, Logger


class AutonomousSystem(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
    """Represents an autonomous system"""
    number: Optional[int]
    name: Optional[str]
    country: Optional[str]
    prefix: Optional[str]
    source: str

    @validator("prefix")
    def validate_prefix(cls, v):
        if not v:
            return v
        try:
            ipaddress.ip_network(v)
        except Exception as e:
            raise ValueError(f"Prefix given could not be parsed by ipaddress module. Likely \"{v}\" has a "
                             f"wrong format: {e}")
        return v

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class using a typical Shodan dictionary."""
        if isinstance(d, List):
            cls.debug("Got a list instead of a dictionary. Usually multiple services of the same host are represented "
                      "as multiple list items by shodan, so this should not be a problem as the AS is the same for all."
                      " Using the first item.")
            d = d[0]
        asn = d.get("asn", None)
        return AutonomousSystem(
            number=int(asn.replace("AS", "")) if asn and isinstance(asn, str) else None,
            name=d.get("isp"),
            country=d.get("location", {}).get("country_code", None),
            prefix=None,  # Not available in Shodan data
            source="shodan"
        )

    @classmethod
    def from_censys(cls, d: Dict):
        return AutonomousSystem(
            number=d["autonomous_system"]["asn"],
            name=d["autonomous_system"]["name"],
            country=d["autonomous_system"]["country_code"],
            prefix=d["autonomous_system"]["bgp_prefix"],
            source="censys"
        )
