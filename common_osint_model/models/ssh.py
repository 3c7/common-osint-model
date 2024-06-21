import base64
from typing import Dict, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger
from common_osint_model.utils import hash_all


class SSHComponentAlgorithms(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents algorithms supported by SSH server."""
    encryption: Optional[List[str]] = None
    key_exchange: Optional[List[str]] = None
    mac: Optional[List[str]] = None
    key_algorithms: Optional[List[str]] = None
    compression: Optional[List[str]] = None

    @classmethod
    def from_shodan(cls, d: Dict) -> Union["SSHComponentAlgorithms", None]:
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
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
            cls.warning(f"Shodan data is missing key: {ke}")
            return None

    @classmethod
    def from_censys(cls, d: Dict) -> Union["SSHComponentAlgorithms", None]:
        """Returns an instance of this class based on Censys data given as dictionary."""
        try:
            return SSHComponentAlgorithms(
                encyption=d["ssh"]["kex_init_message"]["client_to_server_ciphers"],
                key_exchange=d["ssh"]["kex_init_message"]["kex_algorithms"],
                mac=d["ssh"]["kex_init_message"]["server_to_client_macs"],
                key_algorithms=d["ssh"]["kex_init_message"]["host_key_algorithms"],
                compression=d["ssh"]["kex_init_message"]["server_to_client_compression"]
            )
        except KeyError as ke:
            cls.warning(f"Censys data is missing key: {ke}")
            return None

    @classmethod
    def from_binaryedge(cls, d: Dict) -> Union["SSHComponentAlgorithms", None]:
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
            cls.warning(f"BinaryEdge data is missing key: {ke}")
            return None


class SSHComponentKey(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents the public key exposed by the SSH server."""
    # Type represents the ssh-key type, e.g. ssh-rsa
    raw: Optional[str] = None
    type: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    murmur: Optional[str] = None

    @classmethod
    def from_shodan(cls, d: Dict) -> Union["SSHComponentKey", None]:
        """Returns an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
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
            cls.warning(f"Shodan data is missing key: {ke}")
            return None

    @classmethod
    def from_censys(cls, d: Dict) -> Union["SSHComponentKey", None]:
        """Returns an instance of this class based on Censys data given as dictionary."""
        cls.info("Censys data does not contain the key as raw data. The public key can be constructed with given "
                 "data, however, currently this is only supported for RSA keys.")

        try:
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

                cls.info(f"SSH key type is {key_type}. Currently, only RSA SSH keys are supported in Censys model.")
                return SSHComponentKey(
                    type=key_type,
                    sha256=d["ssh"]["server_host_key"]["fingerprint_sha256"]
                )
        except KeyError as ke:
            cls.warning(f"Censys data is missing key: {ke}")
            return None

    @classmethod
    def from_binaryedge(cls, d: Dict) -> Union["SSHComponentKey", None]:
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
            cls.warning(f"BinaryEdge data is missing key: {ke}")
            return None


class SSHComponent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents the SSH component of services."""
    algorithms: Optional[SSHComponentAlgorithms] = None
    key: Optional[SSHComponentKey] = None
    hassh: Optional[str] = None

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method SSHComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        hassh = d.get("ssh", {}).get("hashh", None)

        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_shodan(d),
            key=SSHComponentKey.from_shodan(d),
            hassh=hassh
        )

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        hassh = d.get("ssh", {}).get("hassh_fingerprint", None)
        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_censys(d),
            key=SSHComponentKey.from_censys(d),
            hassh=hassh
        )

    @classmethod
    def from_binaryedge(cls, d: Dict) -> Union["SSHComponent", None]:
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
            return SSHComponent(
                algorithms=SSHComponentAlgorithms.from_binaryedge(algorithms),
                key=SSHComponentKey.from_binaryedge(cypher),
                hassh=hassh
            )
        except KeyError as ke:
            cls.warning(f"BinaryEdge data is missing key: {ke}")
            return None
