import base64
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger
from common_osint_model.utils import hash_all


class SSHComponentAlgorithms(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
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

    @classmethod
    def from_binaryedge(cls, d: Dict):
        """Returns an instance of this class based on BinaryEdge data given as dictionary."""
        return SSHComponentAlgorithms(
            encryption=d["encryption"],
            key_exchange=d["kex"],
            mac=d["mac"],
            key_algorithms=d["server_host_key"],
            compression=d["compression"]
        )


class SSHComponentKey(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents the public key exposed by the SSH server."""
    # Type represents the ssh-key type, e.g. ssh-rsa
    raw: Optional[str]
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
            raw=d["ssh"]["key"],
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

    @classmethod
    def from_binaryedge(cls, d: Dict):
        """Returns an instance of this class based on BinaryEdge data given as dictionary."""
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


class SSHComponent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
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

    @classmethod
    def from_binaryedge(cls, d: Dict):
        """Creates an instance of this class based on BinaryEdge data given as dictionary."""
        cyphers = d["result"]["data"]["cyphers"]
        algorithms = d["result"]["data"]["algorithms"]
        cypher = None
        for c in cyphers:
            if c["cypher"] == "ssh-dss":
                continue
            cypher = c
        return SSHComponent(
            algorithms=SSHComponentAlgorithms.from_binaryedge(algorithms),
            key=SSHComponentKey.from_binaryedge(cypher)
        )
