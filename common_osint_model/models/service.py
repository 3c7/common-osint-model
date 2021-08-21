from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger
from common_osint_model.models.http import HTTPComponent
from common_osint_model.models.ssh import SSHComponent
from common_osint_model.models.tls import TLSComponent
from common_osint_model.models.dns import DNSComponent
from common_osint_model.utils import hash_all


class Service(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents a single service answering connections on specific ports."""
    port: int
    # Banner is optional as not every scanning service offers complete banners as response. Banners might be
    # reconstructed from the data, but some attributes might have the wrong order then (e.g. HTTP headers).
    # The according hashes are also not reliable because of this.
    banner: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
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
    dns: Optional[DNSComponent]
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

        dnsobj = None
        if "dns" in d:
            dnsobj = DNSComponent.from_shodan(d)

        banner = d["data"]
        md5, sha1, sha256, murmur = hash_all(banner.encode("utf-8"))

        return Service(
            port=port,
            banner=d["data"],
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            ssh=sshobj,
            http=httpobj,
            tls=tlsobj,
            dns=dnsobj,
            timestamp=datetime.fromisoformat(d["timestamp"]),
            source="shodan"
        )

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class using a dictionary with typical Censys data."""
        port = d["port"]
        banner = d.get("banner", None)
        md5, sha1, sha256, murmur = None, None, None, None
        if banner:
            md5, sha1, sha256, murmur = hash_all(banner.encode("utf-8"))

        httpobj = None
        if "http" in d:
            httpobj = HTTPComponent.from_censys(d)

        tlsobj = None
        if "tls" in d:
            tlsobj = TLSComponent.from_censys(d)

        sshobj = None
        if "ssh" in d:
            sshobj = SSHComponent.from_censys(d)

        dnsobj = None
        if "dns" in d:
            dnsobj = DNSComponent.from_censys(d)

        return Service(
            port=port,
            banner=banner,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            http=httpobj,
            tls=tlsobj,
            ssh=sshobj,
            dns=dnsobj,
            timestamp=datetime.fromisoformat(d["observed_at"][:-4]),
            source="censys"
        )

    @classmethod
    def from_binaryedge(cls, d: List):
        """Creates an instance of this class using a dictionary with typical BinaryEdge data. Contrary to the other
        scanning services, binaryedge provides multiple entries per port."""
        port = d[0]["target"]["port"]
        type_index: Dict[str, int] = {service["origin"]["type"]: idx for idx, service in enumerate(d)}

        httpobj = None
        if "webv2" in type_index:
            httpobj = HTTPComponent.from_binaryedge(d[type_index["webv2"]])

        tlsobj = None
        if "ssl-simple" in type_index:
            tlsobj = TLSComponent.from_binaryedge(d[type_index["ssl-simple"]])

        sshobj = None
        if "ssh" in type_index:
            sshobj = SSHComponent.from_binaryedge(d[type_index["ssh"]])

        banner = None
        md5, sha1, sha256, murmur = None, None, None, None
        if "service-simple" in type_index:
            banner = d[type_index["service-simple"]]["result"]["data"]["service"]["banner"]
            md5, sha1, sha256, murmur = hash_all(banner.encode("utf-8"))

        return Service(
            port=port,
            http=httpobj,
            tls=tlsobj,
            ssh=sshobj,
            banner=banner,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            source="binaryedge"
        )
