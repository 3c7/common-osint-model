from pydantic import BaseModel
from typing import Optional, Dict
from common_osint_model.models import ShodanDataHandler, CensysDataHandler


class DNSComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
    recursive: Optional[bool] = None

    @classmethod
    def from_shodan(cls, d: Dict):
        return DNSComponent(
            recursive=d.get("dns", {}).get("recursive", False)
        )

    @classmethod
    def from_censys(cls, d: Dict):
        return DNSComponent(
            recursive=d.get("dns", {}).get("server_type", "") == "FORWARDING"
        )
