from common_osint_model.utils import flatten, unflatten, common_model_cn_extraction
from DateTime import DateTime
from mmh3 import hash as mmh3_hash


def from_censys_ipv4(raw: dict) -> dict:
    """
    Converts a Censys IPv4 dictionary into the common format
    :param raw: Censys IPv4 dict
    :return: Common format dict
    """
    flattened = False
    for k in raw.keys():
        if "." in k:
            flattened = True
            break
        elif k == "443" or k == "80" or k == "22" or k == "autonomous_system":
            break

    if flattened:
        raw = unflatten(raw)

    g = {}
    ports = []
    g.update(censys_ipv4_meta_extraction(raw))
    for protocol in raw["protocols"]:
        (port, protocol) = protocol.split("/")
        ports.append(port)
        g.update(censys_ipv4_service_extraction(raw, port, protocol))
    g.update(dict(ports=ports))
    g["domains"] = common_model_cn_extraction(g)
    return g


def from_censys_ipv4_flattened(raw: dict) -> dict:
    """
    Converts a Censys IPv4 dictionary into the common format
    :param raw: Censys IPv4 dict
    :return: Common format dict, flattened
    """
    return flatten(from_censys_ipv4(raw))


def censys_ipv4_meta_extraction(raw: dict) -> dict:
    """
    Extracts metadata from Censys IPv4 dicts
    :param raw: Censys IPv4 dict
    :return: Metadata part of common format dict
    """
    _as = raw.get("autonomous_system", None) or dict()
    return {
        "ip": raw["ip"],
        "as": {
            "number": _as["asn"],
            "name": _as["name"],
            "location": _as["country_code"],
            "prefix": _as["routed_prefix"],
        },
    }


def censys_ipv4_service_extraction(raw: dict, port: str, protocol: str) -> dict:
    """
    Extracts meta information and routes to correct method for service detail extraction.
    :param raw: Censys IPv4 dict
    :param port: Port as str
    :param protocol: Protocol as str
    :return: Service dictionary
    """
    s = raw.get(port, {}).get(protocol, None) or dict()
    service = {
        "timestamp": int(DateTime(raw["updated_at"])),
        "timestamp_readable": DateTime(raw["updated_at"]).ISO8601(),
    }
    keys = s.keys()
    if "banner_decoded" in keys:
        service.update(dict(banner=s["banner_decoded"]))
    if "get" in keys:
        http = censys_ipv4_http_extraction(s["get"])
        service.update({"http": http})
    if "tls" in keys:
        tls = censys_ipv4_tls_extraction(s["tls"])
        service.update({"tls": tls})
    if protocol == 'ssh':
        ssh = censys_ipv4_ssh_extraction(s)
        service.update({"ssh": ssh})
    return {port: service}


def censys_ipv4_http_extraction(s: dict) -> dict:
    """
    Extracts HTTP relevant data out ot service part of Censys IPv4 dict
    :param s: Service part of a censys dict
    :return: Dictionary with HTTP data
    """
    headers = s.get("headers", {})
    for h in headers.get("unknown", []):
        headers.update({h["key"].lower().replace("-", "_"): h["value"]})
    if "unknown" in headers.keys():
        del headers["unknown"]
    return {
        "headers": headers,
        "content": {
            "html": s["body"],
            "hash": {"shodan": mmh3_hash(s["body"]), "sha256": s["body_sha256"]},
            "favicon": {"shodan": None, "sha256": None},
        },
    }


def censys_ipv4_tls_extraction(s: dict) -> dict:
    """
    Extracts TLS relevant data out ot service part of Censys IPv4 dict
    :param s: Service part of a censys dict
    :return: Dictionary with TLS data
    """
    cert = s.get("certificate", {}).get("parsed", {})
    subject = cert.get("subject", None) or dict()
    issuer = cert.get("issuer", None) or dict()
    validity = cert.get("validity", None) or dict()
    common_name = subject.get("common_name", [])
    common_name.extend(cert.get("names", []))
    if len(common_name) == 0:
        common_name = None
    cert_issued = DateTime(validity.get("start", None))
    cert_expires = DateTime(validity.get("end", None))
    cert_length = validity.get("length", None)
    return {
        "certificate": {
            "issuer_dn": cert.get("issuer_dn", None),
            "subject_dn": cert.get("subject_dn", None),
            "issuer": {
                # Censys always uses lists for those kind of attributes
                "common_name": issuer.get("common_name", [None])[0],
                "country": issuer.get("country", [None])[0],
                "locality": issuer.get("locality", [None])[0],
                "province": issuer.get("province", [None])[0],
                "organization": issuer.get("organization", [None])[0],
                "organizational_unit": issuer.get("organizational_unit", [None])[0],
                "email_address": issuer.get("email_address", [None])[0],
            },
            "subject": {
                # Censys always uses lists for those kind of attributes, multiple CNs are okay, though
                "common_name": common_name,
                "country": subject.get("country", [None])[0],
                "locality": subject.get("locality", [None])[0],
                "province": subject.get("province", [None])[0],
                "organization": subject.get("organization", [None])[0],
                "organizational_unit": subject.get("organizational_unit", [None])[0],
                "email_address": subject.get("email_address", [None])[0],
            },
            "validity": {
                "start": int(cert_issued),
                "start_readable": cert_issued.ISO8601(),
                "end": int(cert_expires),
                "end_readable": cert_expires.ISO8601(),
                "length": cert_length
            },
            "fingerprint": {
                "sha1": cert.get("fingerprint_sha1", None),
                "sha256": cert.get("fingerprint_sha256", None)
            }
        }
    }


def censys_ipv4_ssh_extraction(s: dict) -> dict:
    """
    Extracts SSH relevant data out ot service part of Censys IPv4 dict
    :param s: Service part of a censys dict
    :return: Dictionary with SSH data
    """
    v2 = s.get("v2", None) or dict()
    banner = v2.get("banner", None) or dict()
    support = v2.get("support", None) or dict()
    s2c = support.get("server_to_client", None) or dict()
    shk = v2.get("server_host_key", None) or dict()
    return {
        "version": banner.get("raw", None),
        "key_exchange": {
            "algorithms": {
                "compression": s2c.get("compressions", None),
                "encryption": s2c.get("ciphers", None),
                "key_exchange": support.get("kex_algorithms", None),
                "mac": s2c.get("macs", None),
                "key_algorithms": support.get("host_key_algorithms", None)
            }
        },
        "key": {
            "hash": {
                "sha256": shk.get("fingerprint_sha256", None)
            },
            "type": shk.get("key_algorithm", None)
        }
    }
