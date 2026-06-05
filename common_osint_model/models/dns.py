from pydantic import BaseModel
from common_osint_model.models import ShodanDataHandler, CensysDataHandler

from censys_platform.models import Service as CensysService


class DNSComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
    recursive: bool | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        return DNSComponent(
            recursive=d.get("dns", {}).get("recursive", False)
        )

    @classmethod
    def from_censys(cls, service: dict | CensysService):
        if isinstance(service, CensysService):
            if service.dns is not None:
                return DNSComponent(
                    recursive=service.dns.server_type == "FORWARDING"
                )
            return None
        if isinstance(service, dict):
            return DNSComponent(
                recursive=service.get("dns", {}).get("server_type", "") == "FORWARDING"
            )
