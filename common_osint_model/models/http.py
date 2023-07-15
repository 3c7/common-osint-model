import base64
from typing import Dict, List, Optional, Union

import mmh3
from pydantic import BaseModel
from hhhash import hash_from_banner

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger
from common_osint_model.utils import hash_all


class HTTPComponentContentFavicon(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
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

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        favicon = d["result"]["data"]["response"]["favicon"]["content"]
        favicon_bytes = base64.b64decode(favicon.encode("utf-8"))
        md5, sha1, sha256, murmur = hash_all(favicon_bytes)
        shodan_murmur = mmh3.hash(favicon.encode("utf-8"))
        return HTTPComponentContentFavicon(
            raw=favicon,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            murmur=murmur,
            shodan_murmur=shodan_murmur
        )


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
        return HTTPComponentContentSecurity(
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


class HTTPComponentContent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
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

        raw = d["http"].get("html", "")
        if not raw:
            raw = ""

        raw = raw.encode("utf-8")

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

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        """Creates an instance of this class based on BinaryEdge data given as dictionary. Robots and Security.txt are
        not supported by BinaryEdge."""
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
            favicon=HTTPComponentContentFavicon.from_binaryedge(d)
        )


class HTTPComponent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
    """Represents the HTTP component of services."""
    headers: Optional[Dict[str, str]]
    content: Optional[HTTPComponentContent]
    shodan_headers_hash: Optional[str]

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
        banner_keys = lines[0]
        for line in lines:
            if ":" in line:
                key, value = line.split(":", maxsplit=1)
                headers[key.strip()] = value.strip()

        return HTTPComponent(
            headers=headers,
            content=content,
            shodan_headers_hash=d.get("http", {}).get("headers_hash", None)
        )

    @classmethod
    def from_censys(cls, d: Dict):
        """Todo: Is parsing from services.banner better than just looping over the headers found by Censys?"""
        http = d["http"]["response"]
        headers = {}
        for k, v in http["headers"].items():
            if k[0] == "_":
                continue

            headers.update({
                k.replace("_", "-"): " ".join(v)
            })

        banner_lines = d["banner"].replace("\r", "").split("\n")
        banner_keys = banner_lines[0]
        for line in banner_lines:
            if ":" in line:
                k, _ = line.split(":", maxsplit=1)
                banner_keys += "\n" + k
        headers_hash = mmh3.hash(banner_keys.encode("utf-8"))

        return HTTPComponent(
            headers=headers,
            content=HTTPComponentContent.from_censys(d),
            shodan_headers_hash=headers_hash
        )

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        http_response = d["result"]["data"]["response"]
        headers = http_response["headers"]["headers"]
        return HTTPComponent(
            headers=headers,
            content=HTTPComponentContent.from_binaryedge(d)
        )
