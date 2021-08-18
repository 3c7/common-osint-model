import base64
import hashlib
import ipaddress
from abc import ABC
from datetime import datetime
from logging import basicConfig, getLogger
from typing import Optional, Dict, List, Tuple

import mmh3
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
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


class AutonomousSystem(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
    """Represents an autonomous system"""
    number: int
    name: str
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
            cls.info("Got a list instead of a dictionary. Usually multiple services of the same host are represented"
                     " as multiple list items by shodan, so this should not be a problem as the AS is the same for all."
                     " Using the first item.")
            d = d[0]
        return AutonomousSystem(
            number=int(d.get("asn").replace("AS", "")),
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


class HTTPComponentContentFavicon(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Not supported by Censys right now."""
        return None


class HTTPComponentContentRobots(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Not supported by Censys right now."""
        return None


class HTTPComponentContentSecurity(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Not supported by Censys right now."""
        return None


class HTTPComponentContent(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys (2.0) data given as dictionary."""
        http = d["http"]["response"]
        raw = http["body"] if http["body_size"] > 0 else ""
        md5, sha1, sha256, murmur = hash_all(raw.encode("utf-8"))
        return HTTPComponentContent(
            raw=raw,
            length=len(raw),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            favicon=HTTPComponentContentFavicon.from_censys(d),
            robots_txt=HTTPComponentContentRobots.from_censys(d),
            security_txt=HTTPComponentContentSecurity.from_censys(d)
        )


class HTTPComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        http = d["http"]["response"]
        headers = {}
        for k, v in http["headers"].items():
            if k[0] == "_":
                continue

            headers.update({
                k.replace("_", "-"): " ".join(v)
            })
        return HTTPComponent(
            headers=headers,
            content=HTTPComponentContent.from_censys(d)
        )


class TLSComponentCertificateEntity(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        if all(key not in d for key in ["common_name", "locality", "organization", "organizational_unit", "province"]):
            raise KeyError("The dictionary given to TLSComponentCertificateEntity.from_shodan is missing the typical "
                           "shodan keys.")

        c = d.get("country", [])
        st = d.get("province", [])
        l = d.get("locality", [])
        o = d.get("organization", [])
        ou = d.get("organizational_unit", [])
        cn = d.get("common_name", [])
        email = d.get("email_address", [])
        dn = ""
        if c:
            for item in c:
                dn += f"C={item}, "
        if st:
            for item in st:
                dn += f"ST={item}, "
        if l:
            for item in l:
                dn += f"L={item}, "
        if o:
            for item in o:
                dn += f"O={item}, "
        if ou:
            for item in ou:
                dn += f"OU={item}, "
        done = False
        if email and cn:
            if len(email) == 1 and len(cn) == 1:
                dn += f"CN={cn[0]}/Email={email[0]}"
                done = True
            else:
                for item in cn:
                    dn += f"CN={item}, "
                for item in email:
                    dn += f"Email={item}, "
                done = True
        if cn and not done:
            for item in cn:
                dn += f"CN={item}, "

        # This one is probably wrong.
        if email and not done:
            for item in email:
                dn += f"Email={item}, "

        while dn[-1] in [" ", ","]:
            dn = dn[:-1]
        return TLSComponentCertificateEntity(
            dn=dn,
            country=", ".join(c),
            state=", ".join(st),
            locality=", ".join(l),
            organization=", ".join(o),
            organizational_unit=", ".join(ou),
            common_name=", ".join(cn),
            email=", ".join(email)
        )


class TLSComponentCertificate(BaseModel, ShodanDataHandler, CensysDataHandler):
    """Represents certificates."""
    issuer: Optional[TLSComponentCertificateEntity]
    subject: Optional[TLSComponentCertificateEntity]
    issued: Optional[datetime]
    expires: Optional[datetime]
    expired: Optional[bool]
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        return TLSComponentCertificate(
            issuer=TLSComponentCertificateEntity.from_censys(d["issuer"]),
            subject=TLSComponentCertificateEntity.from_censys(d["subject"]),
            issued=None,
            expires=None,
            expired=None,
            alternative_names=d["names"]
        )


class TLSComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        tls = d["tls"]
        return TLSComponent(
            certificate=TLSComponentCertificate.from_censys(tls["certificates"]["leaf_data"])
        )


class SSHComponentAlgorithms(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Returns an instance of this class based on Censys data given as dictionary."""
        return SSHComponentAlgorithms(
            encyption=d["ssh"]["kex_init_message"]["client_to_server_ciphers"],
            key_exchange=d["ssh"]["kex_init_message"]["kex_algorithms"],
            mac=d["ssh"]["kex_init_message"]["server_to_client_macs"],
            key_algorithms=d["ssh"]["kex_init_message"]["host_key_algorithms"],
            compression=d["ssh"]["kex_init_message"]["server_to_client_compression"]
        )


class SSHComponentKey(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Returns an instance of this class based on Censys data given as dictionary."""
        cls.info("Censys data does not contain the key as raw data. The public key can be constructed with given "
                 "data, however, currently this is only supported for RSA keys.")

        if "rsa_public_key" in d["ssh"]["server_host_key"]:
            cls.debug("Seems to be a RSA key. Trying to create public key from modulus and exponent.")
            public_numbers = RSAPublicNumbers(
                e=int.from_bytes(
                    base64.b64decode(d["ssh"]["server_host_key"]["rsa_public_key"]["exponent"]),
                    byteorder="big",
                    signed=False
                ),
                n=int.from_bytes(
                    base64.b64decode(d["ssh"]["server_host_key"]["rsa_public_key"]["modulus"]),
                    byteorder="big",
                    signed=False
                )
            )
            public_key = public_numbers.public_key()
            public_key_string = public_key.public_bytes(
                encoding=Encoding.OpenSSH,
                format=PublicFormat.OpenSSH
            ).decode("utf-8")
            cls.debug(f"Created public key from modulus and exponent: {public_key_string}")
            public_key_raw_data = base64.b64decode(public_key_string.split(" ", maxsplit=1)[1])
            md5, sha1, sha256, murmur = hash_all(public_key_raw_data)
            return SSHComponentKey(
                type="rsa",
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                murmur=murmur
            )
        else:
            key_type = "unknown"
            for key in d["ssh"]["server_host_key"].keys():
                if "public_key" in key:
                    key_type = key.replace("_public_key", "")

            cls.info(f"SSH key type is {key_type}. Currently, only RSA SSH keys are supported in Censys model.")
            return SSHComponentKey(
                type=key_type,
                sha256=d["ssh"]["server_host_key"]["fingerprint_sha256"]
            )


class SSHComponent(BaseModel, ShodanDataHandler, CensysDataHandler):
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

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_censys(d),
            key=SSHComponentKey.from_censys(d)
        )


class Service(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
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
    # Typically hosts consist of different services which might be discovered by different scanning services, so
    # remarking which service was observed by which scanner might be a good idea.
    source: str

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
            tls=tlsobj,
            timestamp=datetime.fromisoformat(d["timestamp"]),
            source="shodan"
        )

    @classmethod
    def from_censys(cls, d: Dict):
        port = d["port"]
        banner = d["banner"]
        httpobj = None
        if "http" in d:
            httpobj = HTTPComponent.from_censys(d)

        tlsobj = None
        if "tls" in d:
            tlsobj = TLSComponent.from_censys(d)

        sshobj = None
        if "ssh" in d:
            sshobj = SSHComponent.from_censys(d)

        return Service(
            port=port,
            banner=banner,
            http=httpobj,
            tls=tlsobj,
            ssh=sshobj,
            timestamp=datetime.fromisoformat(d["observed_at"][:-4]),
            source="censys"
        )


class Host(BaseModel, ShodanDataHandler, CensysDataHandler, Logger):
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

    @classmethod
    def from_censys(cls, d: Dict):
        ip = d["ip"]
        services = []
        for service in d["services"]:
            services.append(Service.from_censys(service))

        return Host(
            ip=ip,
            autonomous_system=AutonomousSystem.from_censys(d),
            services=services
        )
