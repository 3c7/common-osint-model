import ipaddress
import json
from datetime import datetime
from typing import Optional, Dict, List, Union

from pydantic import BaseModel, validator

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger
from common_osint_model.models.autonomous_system import AutonomousSystem
from common_osint_model.models.domain import Domain
from common_osint_model.models.service import Service
from common_osint_model.utils import flatten


class Host(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """This class represents a host and can be used to handle results from the common model in a pythonic way."""
    ip: str
    # Information about the autonomous system the host is assigned to
    autonomous_system: Optional[AutonomousSystem]
    # List of services running (listening) on the IP
    services: Optional[List[Service]]
    # List of open ports also mentioned in the open
    ports: Optional[List[int]]
    # Timestamps for activity tracking
    first_seen: Optional[datetime] = datetime.utcnow()
    last_seen: Optional[datetime] = datetime.utcnow()
    # A list of domains, fqdns, common names - or other attributes which represent domainnames -  assigned to the host
    domains: Optional[List[Domain]]
    # This represents the source where the host information was obtained, e.g. shodan, censys...
    source: Optional[str]
    # Optionally, the used query to find the host can be assigned to the object also which might be useful for comparing
    # different hosts later on
    query: Optional[str]

    @validator("ip")
    def validates_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except Exception as e:
            raise ValueError(f"\"{v}\" is not a correct IP address or at least it is not parseable with the ipaddress"
                             f"module: {e}")
        return v

    @property
    def services_dict(self):
        """Returns the services as dictionary in the form of {port: service}. Uses exclude_none to skip empty keys."""
        # Load the JSON dump, so datetime objects are in iso format.
        json_dict = json.loads(self.json(exclude_none=True))
        json_dict.update({s["port"]: s for s in json_dict["services"]})
        del json_dict["services"]
        return json_dict

    @property
    def flattened_dict(self):
        """Dict in the flattened format."""
        return flatten(self.services_dict)

    @property
    def service_ports(self):
        """Dynamic attribute which loops over available services and grabs the port number. This is kind of redundant
        to the ports attribute, if given, but can help to easily get the values needed for the attribute. Unfortunately
        Pydantic does not support these kind of properties in the data model right now."""
        return [service.port for service in self.services]

    def flattened_json(self) -> str:
        """Returns in the structure formally introduced with the common model."""
        return json.dumps(self.flattened_dict, indent=2)

    @classmethod
    def from_shodan(cls, d: Dict, skip_shodan_domains: Optional[bool] = False):
        if "data" in d and isinstance(d["data"], List):
            d = d["data"]
        domains = []
        domain_strings = []
        if isinstance(d, List):
            for entry in d:
                if "domains" in entry and not skip_shodan_domains:
                    for domain in entry["domains"]:
                        if domain not in domain_strings:
                            domain_strings.append(domain)
                            domains.append(Domain(domain=domain, source="shodan", type="domain"))
                # Check Shodans reverse dns lookups
                if "hostnames" in entry and not skip_shodan_domains:
                    for hostname in entry["hostnames"]:
                        if hostname not in domain_strings:
                            domain_strings.append(hostname)
                            domains.append(Domain(domain=hostname, source="shodan", type="rdns"))
            ip = d[0]["ip_str"]
            services = [Service.from_shodan(service) for service in d]
        else:
            ip = d["ip_str"]
            services = [Service.from_shodan(d)]
        for service in services:
            if service.tls:
                for domain in service.tls.certificate.domains:
                    if domain not in domain_strings:
                        domain_strings.append(domain)
                        domains.append(Domain(
                            domain=domain,
                            first_seen=service.tls.certificate.issued,
                            last_seen=service.tls.certificate.expires,
                            source="shodan",
                            type="common_name"
                        ))
        autonomous_system = AutonomousSystem.from_shodan(d)
        return Host(
            ip=ip,
            autonomous_system=autonomous_system,
            services=services,
            domains=domains,
            source="shodan",
            ports=[service.port for service in services]
        )

    @classmethod
    def from_censys(cls, d: Dict):
        ip = d["ip"]
        services = []
        for service in d["services"]:
            services.append(Service.from_censys(service))

        domains = []
        domain_strings = []
        for service in services:
            if service.tls:
                for domain in service.tls.certificate.domains:
                    if domain not in domain_strings:
                        domain_strings.append(domain)
                        domains.append(Domain(
                            domain=domain,
                            # Currently not given by API
                            # first_seen=service.tls.certificate.issued,
                            # last_seen=service.tls.certificate.expires,
                            source="censys",
                            type="common_name"
                        ))
        return Host(
            ip=ip,
            autonomous_system=AutonomousSystem.from_censys(d),
            services=services,
            domains=domains,
            source="censys",
            ports=[service.port for service in services]
        )

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        """This can either be a complete query result, or a list of services running on the same ip."""
        if isinstance(d, Dict) and "results" in d:
            # This is a complete result dictionary, extract the list of services.
            d = d["results"][list(d["results"].keys())[0]]
        elif isinstance(d, Dict) and "events" in d:
            d = d["events"]

        services = {}
        for service in d:
            port = service["target"]["port"]
            if port not in services:
                services[port] = [service]
            else:
                services[port].append(service)
        services_objects = [Service.from_binaryedge(service) for service in services.values()]
        ip = d[0]["target"]["ip"]
        domains = []
        domain_strings = []
        for service in services_objects:
            if service.tls:
                for domain in service.tls.certificate.domains:
                    if domain not in domain_strings:
                        domain_strings.append(domain)
                        domains.append(Domain(
                            domain=domain,
                            first_seen=service.tls.certificate.issued,
                            last_seen=service.tls.certificate.expires,
                            source="binaryedge",
                            type="common_name"
                        ))
        return Host(
            ip=ip,
            services=services_objects,
            domains=domains,
            source="binaryedge",
            ports=[service.port for service in services_objects]
        )
