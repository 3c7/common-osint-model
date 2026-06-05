import ipaddress
import logging

from pydantic import field_validator, BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler
from censys_platform.models import Routing

logger = logging.getLogger(__name__)


class AutonomousSystem(BaseModel, ShodanDataHandler, CensysDataHandler):
    """Represents an autonomous system"""
    number: int | None = None
    name: str | None = None
    country: str | None = None
    prefix: str | None = None
    source: str
    # TODO: Add ASN Description and Organization

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, v):
        if not v:
            return v
        try:
            ipaddress.ip_network(v)
        except ValueError as e:
            raise ValueError(f"Prefix given could not be parsed by ipaddress module. Likely \"{v}\" has a "
                             f"wrong format: {e}")
        return v

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class using a typical Shodan dictionary."""
        if isinstance(d, list):
            logger.debug("Got a list instead of a dictionary. Usually multiple services of the same host are represented "
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
    def from_censys(cls, autonomous_system: dict | Routing):
        if isinstance(autonomous_system, Routing):
            return AutonomousSystem(
                number=autonomous_system.asn,
                name=autonomous_system.name,
                country=autonomous_system.country_code,
                prefix=autonomous_system.bgp_prefix,
                source="censys"
            )
        
        if isinstance(autonomous_system, dict):
            autonomous_system = autonomous_system.get("autonomous_system", {})
            return AutonomousSystem(
                number=autonomous_system.get("asn", None),
                name=autonomous_system.get("name", None),
                country=autonomous_system.get("country_code", None),
                prefix=autonomous_system.get("bgp_prefix", None),
                source="censys"
            )
        
        return None
