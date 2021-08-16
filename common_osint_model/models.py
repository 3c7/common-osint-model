import base64
import hashlib
import ipaddress
from abc import ABC
from datetime import datetime
from logging import basicConfig, getLogger
from typing import Optional, Dict, List, Tuple

import mmh3
from cryptography.x509 import load_pem_x509_certificate, ExtensionOID, DNSName, ExtensionNotFound
from pydantic import BaseModel, validator

basicConfig(level="INFO")


def hash_all(data: bytes) -> Tuple[str, str, str, str]:
    """
    Helper function to create all hashes for data given.

    :returns: Tuple of hashes as string: md5, sha1, sha256, murmur
    """
    md5, sha1, sha256, murmur = hashlib.md5(), hashlib.sha1(), hashlib.sha256(), mmh3.hash(data)
    md5.update(data), sha1.update(data), sha256.update(data)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), murmur


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
    def from_binaryedge(cls, d: Dict):
        pass


class AutonomousSystem(BaseModel, ShodanDataHandler, Logger):
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

    @classmethod
    def from_shodan(cls, d: Dict):
        """
        Creates an instance of this class using a typical Shodan dictionary.
        """
        if isinstance(d, List):
            cls.info("Got a list instead of a dictionary. Usually multiple services of the same host are represented"
                     " as multiple list items by shodan, so this should not be a problem as the AS is the same for all."
                     " Using the first item.")
            d = d[0]
        return AutonomousSystem(
            number=int(d.get("asn").replace("AS", "")),
            name=d.get("isp"),
            country=d.get("location", {}).get("country_code", None),
            prefix=None  # Not available in Shodan data
        )


class HTTPComponentContentFavicon(BaseModel, ShodanDataHandler, Logger):
    """Represents the favicon which might be included in HTTP components."""
    raw: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
    shodan_murmur: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method HTTPComponentContentFavicon.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        raw = d["http"]["favicon"]["data"]
        raw = base64.b64decode(raw)
        md5, sha1, sha256, murmur = hash_all(raw)
        shodan_murmur = mmh3.hash(d["http"]["favicon"]["data"])
        cls.info("Shodan's favicon hash only hashes the base64 encoded favicon, not the data itself. The hash can be "
                 "found as \"shodan_murmur\" in this instance. \"murmur\" and the other hashes are calculated based on "
                 "the raw data of the favicon.")
        return HTTPComponentContentFavicon(
            raw=d["http"]["favicon"]["data"],
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            shodan_murmur=shodan_murmur
        )


class HTTPComponentContentRobots(BaseModel, ShodanDataHandler):
    """Represents the robots.txt file in webroots."""
    raw: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(
                f"Method HTTPComponentContentRobots.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}.")

        raw = d["http"]["robots"].encode("utf-8")
        md5, sha1, sha256, murmur = hash_all(raw)
        return HTTPComponentContentRobots(
            raw=raw,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur
        )


class HTTPComponentContentSecurity(BaseModel, ShodanDataHandler):
    """Represents the security.txt file in webroots."""
    raw: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(
                f"Method HTTPComponentContentRobots.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}.")

        raw = d["http"]["securitytxt"].encode("utf-8")
        md5, sha1, sha256, murmur = hash_all(raw)
        return HTTPComponentContentRobots(
            raw=raw,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur
        )


class HTTPComponentContent(BaseModel, ShodanDataHandler, Logger):
    """Represents the content (body) of HTTP responses."""
    raw: Optional[str]
    length: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
    favicon: Optional[HTTPComponentContentFavicon]
    robots_txt: Optional[HTTPComponentContentRobots]
    security_txt: Optional[HTTPComponentContentSecurity]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method HTTPComponentContent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        favicon = None
        if "favicon" in d["http"]:
            cls.debug("Favicon key found in Shodan data.")
            favicon = HTTPComponentContentFavicon.from_shodan(d)

        security_txt = None
        if d["http"]["securitytxt"]:
            cls.debug("Security.txt key found in Shodan data.")
            security_txt = HTTPComponentContentSecurity.from_shodan(d)

        robots_txt = None
        if d["http"]["robots"]:
            cls.debug("Robots.txt key found in Shodan data.")
            robots_txt = HTTPComponentContentRobots.from_shodan(d)

        raw = d["http"]["html"].encode("utf-8")
        md5, sha1, sha256, murmur = hash_all(raw)
        return HTTPComponentContent(
            raw=raw,
            length=len(raw),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            favicon=favicon,
            robots_txt=robots_txt,
            security_txt=security_txt
        )


class HTTPComponent(BaseModel, ShodanDataHandler):
    """Represents the HTTP component of services."""
    headers: Optional[Dict[str, str]]
    content: Optional[HTTPComponentContent]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method HTTPComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        content = HTTPComponentContent.from_shodan(d)
        banner = d["data"]
        lines = banner.split("\r\n")
        headers = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", maxsplit=1)
                headers[key.strip()] = value.strip()

        return HTTPComponent(
            headers=headers,
            content=content
        )


class TLSComponentCertificateEntity(BaseModel, ShodanDataHandler):
    """Represents certificate entities, typically issuer and subject."""
    dn: Optional[str]
    country: Optional[str]
    state: Optional[str]
    locality: Optional[str]
    organization: Optional[str]
    organizational_unit: Optional[str]
    common_name: Optional[str]
    email_address: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class using a given Shodan data dictionary."""

        if all(key not in d for key in ["C", "L", "CN", "O", "ST"]):
            raise KeyError("The dictionary given to TLSComponentCertificateEntity.from_shodan is missing the typical "
                           "shodan keys.")

        # C=AT, ST=Steiermark, L=Graz, O=TrustMe Ltd, OU=Certificate Authority, CN=CA/Email=ca@trustme.dom
        c = d.get("C", None)
        st = d.get("ST", None)
        l = d.get("L", None)
        o = d.get("O", None)
        ou = d.get("OU", None)
        cn = d.get("CN", None)
        email = d.get("emailAddress", None)
        dn = ""
        if c:
            dn += f"C={c}, "
        if st:
            dn += f"ST={st}, "
        if l:
            dn += f"L={l}, "
        if o:
            dn += f"O={o}, "
        if ou:
            dn += f"OU={ou}, "
        if cn:
            if not email:
                dn += f"CN={cn}"
            else:
                dn += f"CN={cn}/Email={email}"
        elif not cn and email:
            dn += f"Email={email}"

        while dn[-1] in [",", " "]:
            dn = dn[:-1]

        return TLSComponentCertificateEntity(
            dn=dn,
            country=c,
            state=st,
            locality=l,
            organization=o,
            organizational_unit=ou,
            common_name=cn,
            email=email
        )


class TLSComponentCertificate(BaseModel, ShodanDataHandler):
    """Represents certificates."""
    issuer: Optional[TLSComponentCertificateEntity]
    subject: Optional[TLSComponentCertificateEntity]
    issued: datetime
    expires: datetime
    expired: bool
    # More specifically, this is a certificate extension, but we keep it here because it's easier this way.
    alternative_names: Optional[List[str]]

    @property
    def domains(self) -> List[str]:
        domains = []
        if self.subject.common_name:
            domains.append(self.subject.common_name)
        if self.alternative_names:
            domains.extend(self.alternative_names)
        return list(set(domains))

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method TLSComponentCertificate.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        issuer = TLSComponentCertificateEntity.from_shodan(d["ssl"]["cert"]["issuer"])
        subject = TLSComponentCertificateEntity.from_shodan(d["ssl"]["cert"]["subject"])
        issued = datetime.strptime(d["ssl"]["cert"]["issued"], "%Y%m%d%H%M%SZ")
        expires = datetime.strptime(d["ssl"]["cert"]["expires"], "%Y%m%d%H%M%SZ")
        expired = True if d["ssl"]["cert"]["expired"] in ["true", True] else False
        altnames = []
        for cert in d["ssl"]["chain"]:
            cert = load_pem_x509_certificate(cert.encode("utf-8"))
            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            except ExtensionNotFound:
                continue
            altnames.extend(ext.value.get_values_for_type(DNSName))

        if len(altnames) == 0:
            altnames = None
        else:
            # This removes duplicates
            altnames = list(set(altnames))

        return TLSComponentCertificate(
            issuer=issuer,
            subject=subject,
            issued=issued,
            expires=expires,
            expired=expired,
            alternative_names=altnames
        )


class TLSComponent(BaseModel, ShodanDataHandler):
    """Represents the TLS component of services."""
    certificate: TLSComponentCertificate

    # Todo: Add other attributes relevant to TLS such as CipherSuits etc.

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method TLSComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        return TLSComponent(
            certificate=TLSComponentCertificate.from_shodan(d)
        )


class SSHComponentAlgorithms(BaseModel, ShodanDataHandler):
    """Represents algorithms supported by SSH server."""
    encryption: Optional[List[str]]
    key_exchange: Optional[List[str]]
    mac: Optional[List[str]]
    key_algorithms: Optional[List[str]]
    compression: Optional[List[str]]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method SSHComponentAlgorithms.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")
        return SSHComponentAlgorithms(
            encryption=d["ssh"]["kex"]["encryption_algorithms"],
            key_exchange=d["ssh"]["kex"]["kex_algorithms"],
            mac=d["ssh"]["kex"]["mac_algorithms"],
            key_algorithms=d["ssh"]["kex"]["server_host_key_algorithms"],
            compression=d["ssh"]["kex"]["compression_algorithms"]
        )


class SSHComponentKey(BaseModel, ShodanDataHandler, Logger):
    """Represents the public key exposed by the SSH server."""
    type: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method SSHComponentKey.from_shodan expects parameter d to be a dictionary, but it was "
                            f"{type(d)}.")

        key = d["ssh"]["key"]
        key = base64.b64decode(key)
        md5, sha1, sha256, murmur = hash_all(key)
        return SSHComponentKey(
            type=d["ssh"]["type"],
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur
        )


class SSHComponent(BaseModel, ShodanDataHandler):
    """Represents the SSH component of services."""
    algorithms: Optional[SSHComponentAlgorithms]
    key: Optional[SSHComponentKey]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method SSHComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_shodan(d),
            key=SSHComponentKey.from_shodan(d)
        )


class Service(BaseModel, Logger):
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

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class using a dictionary with typical shodan data."""
        if isinstance(d, List):
            cls.info("The dictionary given is a list. Typically this list represents multiple services. Iterate over "
                     "the list to create Service objects for every item available. "
                     "This method just uses the first item.")
            d = d[0]

        port = d["port"]
        sshobj = None
        if "ssh" in d:
            sshobj = SSHComponent.from_shodan(d)

        httpobj = None
        if "http" in d:
            httpobj = HTTPComponent.from_shodan(d)

        tlsobj = None
        if "ssl" in d:
            tlsobj = TLSComponent.from_shodan(d)

        return Service(
            port=port,
            banner=d["data"],
            ssh=sshobj,
            http=httpobj,
            tls=tlsobj
        )


class Host(BaseModel, ShodanDataHandler, Logger):
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
    def services_dict(self):
        """Returns the services as dictionary in the form of {port: service}. Uses exclude_none to skip empty keys."""
        return {s["port"]: s for s in self.dict(exclude_none=True)["services"]}

    @property
    def ports(self):
        return [service.port for service in self.services]

    @classmethod
    def from_shodan(cls, d: Dict):
        if isinstance(d, List):
            ip = d[0]["ip_str"]
            services = [Service.from_shodan(service) for service in d]
        else:
            ip = d["ip_str"]
            services = [Service.from_shodan(d)]
        autonomous_system = AutonomousSystem.from_shodan(d)
        return Host(
            ip=ip,
            autonomous_system=autonomous_system,
            services=services
        )
