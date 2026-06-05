import base64
import logging

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler
from common_osint_model.utils import hash_all

logger = logging.getLogger(__name__)


class SSHComponentAlgorithms(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
    """Represents algorithms supported by SSH server."""
    encryption: list[str] | None = None
    key_exchange: list[str] | None = None
    mac: list[str] | None = None
    key_algorithms: list[str] | None = None
    compression: list[str] | None = None

    @classmethod
    def from_shodan(cls, d: dict) -> "SSHComponentAlgorithms | None":
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(f"Method SSHComponentAlgorithms.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")
        try:
            return SSHComponentAlgorithms(
                encryption=d["ssh"]["kex"]["encryption_algorithms"],
                key_exchange=d["ssh"]["kex"]["kex_algorithms"],
                mac=d["ssh"]["kex"]["mac_algorithms"],
                key_algorithms=d["ssh"]["kex"]["server_host_key_algorithms"],
                compression=d["ssh"]["kex"]["compression_algorithms"]
            )
        except KeyError as ke:
            logger.warning(f"Shodan data is missing key: {ke}")
            return None

    @classmethod
    def from_censys(cls, d: dict) -> "SSHComponentAlgorithms | None":
        """Returns an instance of this class based on Censys data given as dictionary."""
        try:
            return SSHComponentAlgorithms(
                encryption=d["ssh"]["kex_init_message"]["client_to_server_ciphers"],
                key_exchange=d["ssh"]["kex_init_message"]["kex_algorithms"],
                mac=d["ssh"]["kex_init_message"]["server_to_client_macs"],
                key_algorithms=d["ssh"]["kex_init_message"]["host_key_algorithms"],
                compression=d["ssh"]["kex_init_message"]["server_to_client_compression"]
            )
        except KeyError as ke:
            logger.warning(f"Censys data is missing key: {ke}")
            return None

    @classmethod
    def from_binaryedge(cls, d: dict) -> "SSHComponentAlgorithms | None":
        """Returns an instance of this class based on BinaryEdge data given as dictionary."""
        try:
            return SSHComponentAlgorithms(
                encryption=d["encryption"],
                key_exchange=d["kex"],
                mac=d["mac"],
                key_algorithms=d["server_host_key"],
                compression=d["compression"]
            )
        except KeyError as ke:
            logger.warning(f"BinaryEdge data is missing key: {ke}")
            return None


class SSHComponentKey(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
    """Represents the public key exposed by the SSH server."""
    # Type represents the ssh-key type, e.g. ssh-rsa
    raw: str | None = None
    type: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    murmur: str | None = None

    @classmethod
    def from_shodan(cls, d: dict) -> "SSHComponentKey | None":
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(f"Method SSHComponentKey.from_shodan expects parameter d to be a dictionary, but it was "
                            f"{type(d)}.")

        try:
            key = d["ssh"]["key"]
            key = base64.b64decode(key)
            md5, sha1, sha256, murmur = hash_all(key)
            return SSHComponentKey(
                raw=d["ssh"]["key"],
                type=d["ssh"]["type"],
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                murmur=murmur
            )
        except KeyError as ke:
            logger.warning(f"Shodan data is missing key: {ke}")
            return None

    @classmethod
    def from_censys(cls, d: dict) -> "SSHComponentKey | None":
        """Returns an instance of this class based on Censys data given as dictionary."""
        logger.info("Censys data does not contain the key as raw data. The public key can be constructed with given "
                 "data, however, currently this is only supported for RSA keys.")

        try:
            if "rsa_public_key" in d["ssh"]["server_host_key"]:
                logger.debug("Seems to be a RSA key. Trying to create public key from modulus and exponent.")
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
                logger.debug(f"Created public key from modulus and exponent: {public_key_string}")
                public_key_b64 = public_key_string.split(" ", maxsplit=1)[1]
                public_key_raw_data = base64.b64decode(public_key_b64)
                md5, sha1, sha256, murmur = hash_all(public_key_raw_data)
                return SSHComponentKey(
                    raw=public_key_b64,
                    type="ssh-rsa",
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

                logger.info(f"SSH key type is {key_type}. Currently, only RSA SSH keys are supported in Censys model.")
                return SSHComponentKey(
                    type=key_type,
                    sha256=d["ssh"]["server_host_key"]["fingerprint_sha256"]
                )
        except KeyError as ke:
            logger.warning(f"Censys data is missing key: {ke}")
            return None

    @classmethod
    def from_binaryedge(cls, d: dict) -> "SSHComponentKey | None":
        """Returns an instance of this class based on BinaryEdge data given as dictionary."""
        try:
            public_key_raw_data = base64.b64decode(d["key"])
            md5, sha1, sha256, murmur = hash_all(public_key_raw_data)
            return SSHComponentKey(
                raw=d["key"],
                type=d["cypher"],
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                murmur=murmur
            )
        except KeyError as ke:
            logger.warning(f"BinaryEdge data is missing key: {ke}")
            return None


class SSHComponent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
    """Represents the SSH component of services."""
    algorithms: SSHComponentAlgorithms | None = None
    key: SSHComponentKey | None = None
    hassh: str | None = None

    @classmethod
    def from_shodan(cls, d: dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, dict):
            raise TypeError(f"Method SSHComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        hassh = d.get("ssh", {}).get("hashh", None)

        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_shodan(d),
            key=SSHComponentKey.from_shodan(d),
            hassh=hassh
        )

    @classmethod
    def from_censys(cls, d: dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        hassh = d.get("ssh", {}).get("hassh_fingerprint", None)
        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_censys(d),
            key=SSHComponentKey.from_censys(d),
            hassh=hassh
        )

    @classmethod
    def from_binaryedge(cls, d: dict) -> "SSHComponent | None":
        """Creates an instance of this class based on BinaryEdge data given as dictionary."""
        try:
            cyphers = d["result"]["data"]["cyphers"]
            algorithms = d["result"]["data"]["algorithms"]
            hassh = d["result"]["data"]["hassh"]["hassh"]
            cypher = None
            for c in cyphers:
                if c["cypher"] == "ssh-dss":
                    continue
                cypher = c
            key = SSHComponentKey.from_binaryedge(cypher) if cypher is not None else None
            return SSHComponent(
                algorithms=SSHComponentAlgorithms.from_binaryedge(algorithms),
                key=key,
                hassh=hassh
            )
        except KeyError as ke:
            logger.warning(f"BinaryEdge data is missing key: {ke}")
            return None
