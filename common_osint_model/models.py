import ipaddress
from datetime import datetime
from typing import Optional, Dict, List

from pydantic import BaseModel, validator


class AutonomousSystem(BaseModel):
    """Represents an autonomous system"""
    number: int
    name: str
    country: Optional[str]
    prefix: Optional[str]

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


class HTTPComponentContentFavicon(BaseModel):
    """Represents the favicon which might be included in HTTP components."""
    raw: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]


class HTTPComponentContent(BaseModel):
    """Represents the content (body) of HTTP responses."""
    raw: Optional[str]
    length: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
    favicon: Optional[HTTPComponentContentFavicon]


class HTTPComponent(BaseModel):
    """Represents the HTTP component of services."""
    headers: Optional[Dict[str, str]]
    content: Optional[HTTPComponentContent]


class TLSComponentCertificateEntity(BaseModel):
    """Represents certificate entities, typically issuer and subject."""
    dn: Optional[str]
    country: Optional[str]
    state: Optional[str]
    locality: Optional[str]
    organization: Optional[str]
    organizational_unit: Optional[str]
    common_name: Optional[str]
    email_address: Optional[str]


class TLSComponentCertificate(BaseModel):
    """Represents certificates."""
    issuer: Optional[TLSComponentCertificateEntity]
    subject: Optional[TLSComponentCertificateEntity]
    issued: datetime
    expired: datetime
    # More specifically, this is a certificate extension, but we keep it here because it's easier this way.
    alternative_names: Optional[List[str]]

    @property
    def domains(self) -> List[str]:
        domains = []
        if self.subject.common_name:
            domains.append(self.subject.common_name)
        if self.alternative_names:
            domains.extend(self.alternative_names)
        return domains


class TLSComponent(BaseModel):
    """Represents the TLS component of services."""
    certificate: TLSComponentCertificate
    # Todo: Add other attributes relevant to TLS such as CipherSuits etc.


class SSHComponentAlgorithms(BaseModel):
    """Represents algorithms supported by SSH server."""
    encryption: Optional[List[str]]
    key_exchange: Optional[List[str]]
    mac: Optional[List[str]]
    key_algorithms: Optional[List[str]]
    compression: Optional[List[str]]


class SSHComponentKey(BaseModel):
    """Represents the public key exposed by the SSH server."""
    type: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]


class SSHComponent(BaseModel):
    """Represents the SSH component of services."""
    algorithms: Optional[SSHComponentAlgorithms]
    key: Optional[SSHComponentKey]


class Service(BaseModel):
    """Represents a single service answering connections on specific ports."""
    port: int
    # Banner is optional as not every scanning service offers complete banners as response. Banners might be
    # reconstructed from the data, but some attributes might have the wrong order then (e.g. HTTP headers).
    banner: Optional[str]
    # Every service object should include these timestamps. "timestamp" can be used for tracking the observation
    # timestamp from scanning services (e.g. Shodan)
    first_seen: Optional[datetime] = datetime.utcnow()
    last_seen: Optional[datetime] = datetime.utcnow()
    timestamp: Optional[datetime]
    # We need to include every possible service component here. In order to not export empty dictionary keys, the class
    # object can be exported with dict(exclude_none=True), so e.g. empty tls keys are skipped.
    http: Optional[HTTPComponent]
    tls: Optional[TLSComponent]
    ssh: Optional[SSHComponent]


class Host(BaseModel):
    """This class represents a host and can be used to handle results from the common model in a pythonic way."""
    ip: str
    autonomous_system: AutonomousSystem
    services: List[Service]
    first_seen: Optional[datetime] = datetime.utcnow()
    last_seen: Optional[datetime] = datetime.utcnow()

    @validator("ip")
    def validates_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except Exception as e:
            raise ValueError(f"\"{v}\" is not a correct IP address or at least it is not parseable with the ipaddress"
                             f"module: {e}")
        return v

    @property
    def service_dict(self):
        """Returns the services as dictionary in the form of {port: service}. Uses exclude_none to skip empty keys."""
        return {s["port"]: s for s in self.dict(exclude_none=True)["services"]}
