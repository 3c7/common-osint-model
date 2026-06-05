import base64
import logging

import mmh3  # type: ignore[import]
from pydantic import BaseModel
from hhhash import hash_from_banner

from common_osint_model.models import (
    ShodanDataHandler,
    CensysDataHandler,
    BinaryEdgeDataHandler,
)
from common_osint_model.utils import hash_all

from censys_platform.models import Service as CensysService
from censys_platform.models import EndpointScanState

logger = logging.getLogger(__name__)


class HTTPComponentContentFavicon(
    BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler
):
    """Represents the favicon which might be included in HTTP components."""

    raw: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None
    shodan_murmur: str | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContentFavicon.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )

        raw = d["http"]["favicon"]["data"]
        raw = base64.b64decode(raw)
        md5, sha1, sha256, murmur = hash_all(raw)
        shodan_murmur = str(mmh3.hash(d["http"]["favicon"]["data"]))
        logger.info(
            "Shodan's favicon hash only hashes the base64 encoded favicon, not the data itself. The hash can be "
            'found as "shodan_murmur" in this instance. "murmur" and the other hashes are calculated based on '
            "the raw data of the favicon."
        )
        return HTTPComponentContentFavicon(
            raw=d["http"]["favicon"]["data"],
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            shodan_murmur=shodan_murmur,
        )

    @classmethod
    def from_censys(cls, d: dict):
        """
        Not supported by Censys right now.
        TODO: Censys implemented Favicons.
        """
        return None

    @classmethod
    def from_binaryedge(cls, d: dict | list):
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContentFavicon.from_binaryedge expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )
        favicon = d["result"]["data"]["response"]["favicon"]["content"]
        favicon_bytes = base64.b64decode(favicon.encode("utf-8"))
        md5, sha1, sha256, murmur = hash_all(favicon_bytes)
        shodan_murmur = str(mmh3.hash(favicon.encode("utf-8")))
        return HTTPComponentContentFavicon(
            raw=favicon,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            shodan_murmur=shodan_murmur,
        )


class HTTPComponentContentRobots(BaseModel, ShodanDataHandler, CensysDataHandler):
    """Represents the robots.txt file in webroots."""

    raw: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContentRobots.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )

        raw = d["http"]["robots"].encode("utf-8")
        md5, sha1, sha256, murmur = hash_all(raw)
        return HTTPComponentContentRobots(
            raw=raw, md5=md5, sha1=sha1, sha256=sha256, murmur=murmur
        )

    @classmethod
    def from_censys(cls, d: dict):
        """Not supported by Censys right now."""
        return None


class HTTPComponentContentSecurity(BaseModel, ShodanDataHandler, CensysDataHandler):
    """Represents the security.txt file in webroots."""

    raw: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContentRobots.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )

        raw = d["http"]["securitytxt"].encode("utf-8")
        md5, sha1, sha256, murmur = hash_all(raw)
        return HTTPComponentContentSecurity(
            raw=raw, md5=md5, sha1=sha1, sha256=sha256, murmur=murmur
        )

    @classmethod
    def from_censys(cls, d: dict):
        """Not supported by Censys right now."""
        return None


class HTTPComponentContent(
    BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler
):
    """Represents the content (body) of HTTP responses."""

    raw: str | None = None
    length: int | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None
    favicon: HTTPComponentContentFavicon | None = None
    robots_txt: HTTPComponentContentRobots | None = None
    security_txt: HTTPComponentContentSecurity | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContent.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )

        favicon = None
        if "favicon" in d.get("http", {}):
            logger.debug("Favicon key found in Shodan data.")
            favicon = HTTPComponentContentFavicon.from_shodan(d)

        security_txt = None
        if d.get("http", {}).get("securitytxt"):
            logger.debug("Security.txt key found in Shodan data.")
            security_txt = HTTPComponentContentSecurity.from_shodan(d)

        robots_txt = None
        if d.get("http", {}).get("robots"):
            logger.debug("Robots.txt key found in Shodan data.")
            robots_txt = HTTPComponentContentRobots.from_shodan(d)

        raw_str = d["http"].get("html", "")
        if not raw_str:
            raw_str = ""

        try:
            raw_bytes = raw_str.encode("utf-8")
        except UnicodeEncodeError as uee:
            # TODO: This is very ugly, but spontanously I can't find a solution for the weird Shodan encoding issue.
            logger.error(f"UnicodeEncodeError during Shodan result encoding: {uee}")
            logger.warning("Using empty strings as HTML body.")
            raw_bytes = "".encode("utf-8")

        md5, sha1, sha256, murmur = hash_all(raw_bytes)
        return HTTPComponentContent(
            raw=raw_str,
            length=len(raw_bytes),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            favicon=favicon,
            robots_txt=robots_txt,
            security_txt=security_txt,
        )

    @classmethod
    def from_censys(cls, service: dict | CensysService):
        if isinstance(service, CensysService):
            endpoints = service.endpoints
            if isinstance(endpoints, list):
                for endpoint in endpoints:
                    if isinstance(endpoint, EndpointScanState) and endpoint.http is not None:
                        http_body = endpoint.http.body
                        if http_body is None:
                            continue
                        md5, sha1, sha256, murmur = hash_all(http_body.encode("utf-8"))
                        # Overwrite available hashes with CensysAPI data
                        if endpoint.http.body_hash_sha1 is not None:
                            sha1 = endpoint.http.body_hash_sha1
                        if endpoint.http.body_hash_sha256 is not None:
                            sha256 = endpoint.http.body_hash_sha256
                        
                        return HTTPComponentContent(
                            raw=http_body,
                            length=len(http_body),
                            md5=md5,
                            sha1=sha1,
                            sha256=sha256,
                            murmur=murmur,
                            # TODO: Implement Favicon, Robots, Security
                            #favicon=HTTPComponentContentFavicon.from_censys(service),
                            #robots_txt=HTTPComponentContentRobots.from_censys(service),
                            #security_txt=HTTPComponentContentSecurity.from_censys(service),
                        )
            # Fallback, if no endpoint or no HTTP endpoint
            return None

        if isinstance(service, dict):
            """Creates an instance of this class based on Censys (2.0) data given as dictionary."""
            http = service["http"]["response"]
            raw = http["body"] if http["body_size"] > 0 else ""
            md5, sha1, sha256, murmur = hash_all(raw.encode("utf-8"))
            return HTTPComponentContent(
                raw=raw,
                length=len(raw),
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                murmur=murmur,
                favicon=HTTPComponentContentFavicon.from_censys(service),
                robots_txt=HTTPComponentContentRobots.from_censys(service),
                security_txt=HTTPComponentContentSecurity.from_censys(service),
            )

    @classmethod
    def from_binaryedge(cls, d: dict | list):
        """Creates an instance of this class based on BinaryEdge data given as dictionary. Robots and Security.txt are
        not supported by BinaryEdge."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponentContent.from_binaryedge expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )
        http_response = d["result"]["data"]["response"]
        raw = http_response["body"]["content"]
        md5, sha1, sha256, murmur = hash_all(raw.encode("utf-8"))
        return HTTPComponentContent(
            raw=raw,
            length=len(raw),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            favicon=HTTPComponentContentFavicon.from_binaryedge(d),
        )


class HTTPComponent(
    BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler
):
    """Represents the HTTP component of services."""

    headers: dict[str, str] | None = None
    content: HTTPComponentContent | None = None
    shodan_headers_hash: str | None = None
    hhhash: str | None = None
    status_code: int | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponent.from_shodan expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )

        content = HTTPComponentContent.from_shodan(d)
        banner = d["data"]
        lines = banner.split("\r\n")
        headers = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", maxsplit=1)
                headers[key.strip()] = value.strip()
        headers_hash = d.get("http", {}).get("headers_hash", None)
        return HTTPComponent(
            headers=headers,
            content=content,
            shodan_headers_hash=str(headers_hash) if headers_hash else None,
            hhhash=hash_from_banner(banner),
        )

    @classmethod
    def from_censys(cls, service: dict | CensysService):
        if isinstance(service, CensysService):
            endpoints = service.endpoints
            if isinstance(endpoints, list):
                for endpoint in endpoints:
                    if isinstance(endpoint, EndpointScanState) and endpoint.http is not None:
                        headers: dict[str, str] = dict()
                        # Store Header
                        if endpoint.http.headers is not None:
                            for header_name, header_values in endpoint.http.headers.items():
                                if header_values.headers is not None and isinstance(header_values.headers, list):
                                    for header_value in header_values.headers:
                                        if isinstance(header_value, str):
                                            headers[header_name] = header_value
                        banner = service.banner
                        if banner is None:
                            continue
                        banner_lines = banner.replace("\r", "").split("\n")
                        banner_keys = banner_lines[0]
                        for line in banner_lines:
                            if ":" in line:
                                k, _ = line.split(":", maxsplit=1)
                                banner_keys += "\n" + k
                        headers_hash = str(mmh3.hash(banner_keys.encode("utf-8")))

                        return HTTPComponent(
                            headers=headers,
                            content=HTTPComponentContent.from_censys(service),
                            shodan_headers_hash=headers_hash,
                            hhhash=hash_from_banner(banner),
                            status_code=endpoint.http.status_code
                        )
            # Fallback, if no endpoint or no HTTP endpoint
            return None

        if isinstance(service, dict):
            return cls._from_censys_dict(d=service)

    @classmethod
    def from_binaryedge(cls, d: dict | list):
        if not isinstance(d, dict):
            raise TypeError(
                f"Method HTTPComponent.from_binaryedge expects parameter d to be a dictionary, "
                f"but it was {type(d)}."
            )
        http_response = d["result"]["data"]["response"]
        headers = http_response["headers"]["headers"]
        return HTTPComponent(
            headers=headers, content=HTTPComponentContent.from_binaryedge(d)
        )

    @classmethod
    def _from_censys_dict(cls, d: dict):
        """Todo: Is parsing from services.banner better than just looping over the headers found by Censys?"""
        http = d["http"]["response"]
        headers = {}
        for k, v in http["headers"].items():
            if k[0] == "_":
                continue

            headers.update({k.replace("_", "-"): " ".join(v)})

        banner_lines = d["banner"].replace("\r", "").split("\n")
        banner_keys = banner_lines[0]
        for line in banner_lines:
            if ":" in line:
                k, _ = line.split(":", maxsplit=1)
                banner_keys += "\n" + k
        headers_hash = str(mmh3.hash(banner_keys.encode("utf-8")))

        return HTTPComponent(
            headers=headers,
            content=HTTPComponentContent.from_censys(d),
            shodan_headers_hash=headers_hash,
            hhhash=hash_from_banner(d["banner"]),
        )
