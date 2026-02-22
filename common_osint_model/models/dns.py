from pydantic import BaseModel
from typing import Optional, Dict
from common_osint_model.models import ShodanDataHandler, CensysDataHandler

from censys_platform.models import Service as CensysService


class DNSComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
    recursive: Optional[bool] = None

    @classmethod
    def from_shodan(cls, d: Dict):
        return DNSComponent(
            recursive=d.get("dns", {}).get("recursive", False)
        )

    @classmethod
    def from_censys(cls, service: Dict | CensysService):
        if isinstance(service, CensysService):
            if service.dns is not None:
                return DNSComponent(
                    recursive=service.dns.server_type == "FORWARDING"
                )
            return None
        if isinstance(service, Dict):
            return DNSComponent(
                recursive=service.get("dns", {}).get("server_type", "") == "FORWARDING"
            )
