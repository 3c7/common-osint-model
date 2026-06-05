import logging
from datetime import datetime, UTC

from pydantic import BaseModel, Field

from common_osint_model.models import (
    ShodanDataHandler,
    CensysDataHandler,
    BinaryEdgeDataHandler,
)
from common_osint_model.models.http import HTTPComponent
from common_osint_model.models.ssh import SSHComponent
from common_osint_model.models.tls import TLSComponent
from common_osint_model.models.dns import DNSComponent
from common_osint_model.utils import hash_all

from censys_platform.models import Service as CensysService

logger = logging.getLogger(__name__)


class Service(
    BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler
):
    """Represents a single service answering connections on specific ports."""

    port: int
    protocol: str | None = None
    # Banner is optional as not every scanning service offers complete banners as response. Banners might be
    # reconstructed from the data, but some attributes might have the wrong order then (e.g. HTTP headers).
    # The according hashes are also not reliable because of this.
    banner: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None
    ja4tscan: str | None = None
    # Every service object should include these timestamps. "timestamp" can be used for tracking the observation
    # timestamp from scanning services (e.g. Shodan)
    first_seen: datetime | None = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime | None = Field(default_factory=lambda: datetime.now(UTC))
    timestamp: datetime | None = None
    # We need to include every possible service component here. In order to not export empty dictionary keys, the class
    # object can be exported with dict(exclude_none=True), so e.g. empty tls keys are skipped.
    http: HTTPComponent | None = None
    tls: TLSComponent | None = None
    ssh: SSHComponent | None = None
    dns: DNSComponent | None = None
    # Typically hosts consist of different services which might be discovered by different scanning services, so
    # remarking which service was observed by which scanner might be a good idea.
    source: str

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class using a dictionary with typical shodan data."""
        if isinstance(d, list):
            logger.info(
                "The dictionary given is a list. Typically this list represents multiple services. Iterate over "
                "the list to create Service objects for every item available. "
                "This method just uses the first item."
            )
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
            source="shodan",
        )

    @classmethod
    def from_censys(cls, service: dict | CensysService):
        if isinstance(service, CensysService):
            port = service.port
            protocol = None
            if service.protocol is not None and not service.protocol == "UNKNOWN":
                protocol = service.protocol
            else:
                protocol = service.transport_protocol
            
            # Set various banner and pivot hashes
            banner = service.banner
            md5, sha1, sha256, murmur = None, None, None, None
            if banner:
                md5, sha1, sha256, murmur = hash_all(banner.encode("utf-8"))
            # Overwrite calcuated sha256 hash with the one from source
            sha256 = service.banner_hash_sha256
            ja4tscan = None
            if service.ja4tscan is not None:
                ja4tscan = service.ja4tscan.fingerprint
            
            tls = None
            if service.tls is not None:
                tls = TLSComponent.from_censys(service=service)
            
            http = None
            if service.endpoints is not None:
                http = HTTPComponent.from_censys(service=service)

            dns = None
            if service.dns is not None:
                dns = DNSComponent.from_censys(service=service)
            
            # TODO: Implement SSHComponent

            timestamp = None
            if service.scan_time is not None:
                try:
                    timestamp = datetime.fromisoformat(service.scan_time)
                except ValueError as ve:
                    logger.warning(
                        f"{service.scan_time} could not be parsed as timestamp: {ve}"
                    )
            if port is None:
                raise ValueError("Service port is None")
            return Service(
                port=port,
                protocol=protocol,
                banner=banner,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                murmur=murmur,
                ja4tscan=ja4tscan,
                timestamp=timestamp,
                tls=tls,
                http=http,
                dns=dns,
                source="censys"
            )

        if isinstance(service, dict):
            return cls._from_censys_dict(d=service)
        

    @classmethod
    def from_binaryedge(cls, d: list):
        """Creates an instance of this class using a dictionary with typical BinaryEdge data. Contrary to the other
        scanning services, binaryedge provides multiple entries per port."""
        port = d[0]["target"]["port"]
        type_index: dict[str, int] = {
            service["origin"]["type"]: idx for idx, service in enumerate(d)
        }

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
            banner = d[type_index["service-simple"]]["result"]["data"]["service"].get(
                "banner", None
            )
        if banner:
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
            source="binaryedge",
        )

    @classmethod
    def _from_censys_dict(cls, d: dict):
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

        timestamp = None
        if "observed_at" in d:
            try:
                timestamp = datetime.fromisoformat(d["observed_at"])
            except ValueError as ve:
                logger.warning(
                    f"{d['observed_at']} could not be parsed as timestamp: {ve}"
                )
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
            timestamp=timestamp,
            source="censys",
        )
