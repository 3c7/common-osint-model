import re
from DateTime import DateTime
from datetime import datetime
from typing import Union
from common_osint_model.utils import flatten, common_model_cn_extraction, sha256_from_body_string
from binascii import hexlify
from hashlib import sha256
from base64 import b64decode


def from_shodan(raw: Union[list, dict]) -> dict:
    """
    Turn an expected Shodan dictionary into a generic format
    :param raw: Shodan list or dictionary from host queries
    :return: Generic host describing dictionary
    """
    g = {}
    services = []
    if isinstance(raw, dict):
        if isinstance(raw.get("data", ""), list):
            services.extend(raw["data"])
        else:
            services.append(raw)
    elif isinstance(raw, list):
        if len(raw) == 1:
            raw = raw[0]
            if isinstance(raw.get("data", ""), list):
                services.extend(raw["data"])
            else:
                services.append(raw)
        else:
            services.extend(raw)
    else:
        raise TypeError("Given parameter 'raw' must be either a list or a dict.")
    # Get the meta data
    g.update(shodan_meta_extraction(services))
    # Get data for every service
    ports = []
    for s in services:
        ports.append(s["port"])
        g.update(shodan_service_extraction(s))
    g.update(dict(ports=ports))
    g["domains"].extend(common_model_cn_extraction(g))
    return g


def from_shodan_flattened(raw: Union[list, dict]) -> dict:
    """
    Turn an expected Shodan dictionary into a generic format
    :param raw: Shodan list or dictionary from host queries
    :return: Generic host describing dictionary, flattened
    """
    return flatten(from_shodan(raw))


def shodan_meta_extraction(raw: Union[dict, list]) -> dict:
    """
    Returns a dictionary containing all the meta information from a Shodan host or service
    :param raw: Either a service dict or a host list object
    :return: Dictionary containing all meta information
    """
    g = {}
    if isinstance(raw, dict):
        o = raw
    elif isinstance(raw, list):
        o = raw[0]
    else:
        raise TypeError("Given parameter 'raw' must be either a list or a dict.")
    g.update(
        {
            "as": {
                "number": o.get("asn", None),
                "name": o.get("isp", None),
                "location": o.get("location", {}).get("country_code", None),
                "prefix": None,  # Todo: Check of routed prefix is given in censys output
            },
            "domains": [],
            "org": o.get("org", None),
            "ip": o.get("ip_str"),
            "location": {
                "city": o.get("city", None),
                "country": o.get("country_name", None),
                "country_code": o.get("country_code", None),
                "postal_code": o.get("postal_code", None),
                "coordinates": {
                    "latitude": o.get("latitude", None),
                    "longitude": o.get("longitude", None)
                }
            }
        }
    )
    for domain in o.get("domains", []):
        g["domains"].append({"type": "shodan-domain", "value": domain})
    for hostname in o.get("hostnames", []):
        g["domains"].append({"type": "shodan-hostname", "value": hostname})
    return g


def shodan_service_extraction(s: dict) -> dict:
    """
    Returns a dictionary containing a properly formatted service based on a shodan raw dictionary
    :param s: Shodan service dictionary
    :return: Porperly formatted dictionary
    """
    g = {}
    p = s["port"]
    g.update(
        {
            p: {
                "banner": s["data"],
                "timestamp": int(DateTime(s["timestamp"])),
                "timestamp_readable": DateTime(s["timestamp"]).ISO8601(),
            }
        }
    )
    k = s.keys()

    if "http" in k or s["data"][:4] == "HTTP":
        g[p].update(shodan_http_extraction(s))
    if "ssl" in k:
        g[p].update(shodan_ssl_extraction(s))
    if "ssh" in k:
        g[p].update(shodan_ssh_extraction(s))
    return g


def shodan_http_extraction(s: dict) -> dict:
    """
    Extracts http(s) specific values from shodan service dict
    :param s: Shodan service dictionary
    :return: Properly formatted, service related dictionary
    """
    http = s.get("http", None) or dict()
    headers = {}
    for line in s["data"].split("\n"):
        line = line.strip()
        if not ":" in line:
            continue
        h = line.split(":")
        headers.update({h[0].lower().replace("-", "_"): ":".join(h[1:]).strip()})
    favicon = http.get("favicon", None) or dict()
    favicon_data = favicon.get("data", None)
    favicon_hash = favicon.get("hash", None)
    favicon_sha256 = None
    if favicon:
        favicon_decoded = b64decode(favicon_data)
        h = sha256()
        h.update(favicon_decoded)
        favicon_sha256 = hexlify(h.digest()).decode("ascii")
    return {
        "http": {
            "headers": headers,
            "content": {
                "html": http.get("html", None),
                "hash": {
                    "shodan": http.get("html_hash", None),
                    "sha256": sha256_from_body_string(http.get("html", None) or "")
                },
                "favicon": {"shodan": favicon_hash, "sha256": favicon_sha256},
            },
        }
    }


def shodan_ssl_extraction(s: dict) -> dict:
    """
    Extracts ssl/tls specific values from shodan service dict
    :param s: Shodan service dictionary
    :return: Properly formatted, service related dictionary
    """
    ssl = s.get("ssl", None) or dict()
    cert = ssl.get("cert", {})
    subject = cert.get("subject", None) or dict()
    issuer = cert.get("issuer", None) or dict()
    fingerprint = cert.get("fingerprint", None) or dict()
    dhparams = ssl.get("dhparams", None) or dict()
    common_name = subject.get("CN", None)
    common_names = set()
    if common_name:
        common_names.add(common_name)
    for ext in ssl.get("extensions", []):
        if ext["name"] == "subjectAltName":
            for domain in re.split(r"(\\x[0-9a-z]{2}|\\[a-z^x]{1})", ext["date"]):
                if "." in domain:
                    common_names.add(domain)
    cert_issued = int(datetime.strptime(cert.get("issued", None), "%Y%m%d%H%M%SZ").timestamp())
    cert_expires = int(datetime.strptime(cert.get("expires", None), "%Y%m%d%H%M%SZ").timestamp())
    return {
        "tls": {
            "certificate": {
                "subject": {
                    "country": subject.get("C", None),
                    "province": subject.get("ST", None),
                    "locality": subject.get("L", None),
                    "common_name": list(common_names),
                    "organization": subject.get("O", None),
                    "organizational_unit": subject.get("OU", None),
                    "email_address": subject.get("email", None),
                },
                "issuer": {
                    "country": issuer.get("C", None),
                    "province": issuer.get("ST", None),
                    "locality": issuer.get("L", None),
                    "common_name": issuer.get("CN", None),
                    "organization": issuer.get("O", None),
                    "organizational_unit": issuer.get("OU", None),
                    "email_address": issuer.get("email", None),
                },
                "fingerprint": {
                    "sha1": fingerprint.get("sha1", None),
                    "sha256": fingerprint.get("sha256", None),
                },
                "serial_number": str(int(cert.get("serial", None))),
                "validity": {
                    "start": cert_issued,
                    "start_readable": DateTime(cert_issued, 'UTC').ISO8601(),
                    "end": cert_expires,
                    "end_readable": DateTime(cert_expires, 'UTC').ISO8601(),
                    "length": cert_expires - cert_issued,
                }
            },
            "dhparam": {
                "bits": dhparams.get("bits", None),
                "generator": dhparams.get("generator", None),
            },
            "cipher": {
                "id": None,
                "name": ssl.get("cipher", {}).get("name", None),
                "bits": ssl.get("cipher", {}).get("bits", None),
            },
            "ja3s": ssl.get("ja3s", None),
            "jarm": ssl.get("jarm", None)
        }
    }


def shodan_ssh_extraction(s: dict) -> dict:
    """
    Extracts ssh specific values from shodan service dict
    :param s: Shodan service dictionary
    :return: Properly formatted, service related dictionary
    """
    ssh = s.get("ssh", None) or dict()
    key_exchange = ssh.get("kex", None) or dict()
    h = sha256()
    h.update(b64decode(ssh.get("key", None)))
    return {
        "ssh": {
            "version": s["data"].split("Key type")[0].strip(),
            "key_exchange": {
                "algorithms": {
                    "compression": key_exchange.get("compression_algorithms", None),
                    "encryption": key_exchange.get("encryption_algorithms", None),
                    "key_exchange": key_exchange.get("kex_algorithms", None),
                    "mac": key_exchange.get("mac_algorithms", None),
                    "key_algorithms": key_exchange.get(
                        "server_host_key_algorithms", None
                    ),
                }
            },
            "key": {
                "hash": {
                    "sha256": hexlify(h.digest()).decode("ascii")
                },
                "type": ssh.get("type", None),
            },
        }
    }
