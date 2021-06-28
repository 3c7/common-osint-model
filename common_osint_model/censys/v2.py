from typing import Dict, List, Any

from mmh3 import hash as mmh3_hash

from common_osint_model.utils import sha256_from_body_string, flatten


def from_censys(raw: Dict) -> Dict:
    """
    Convert Censys data model to the common data model.

    :param raw: Censys Search 2.0 dictionary
    """
    common = {}
    common.update(
        censys_meta_extraction(raw)
    )

    for service in raw.get("services", []):
        common.update(censys_extract_service(service))
    return common


def from_censys_flattened(raw: Dict) -> Dict:
    return flatten(from_censys(raw))


def censys_meta_extraction(raw: Dict) -> Dict:
    """
    Returns all metadata.

    :param raw: Censys Search 2.0 dictionary
    """
    _as = raw.get("autonomous_system", {})
    return {
        "ip": raw.get("ip", "None"),
        "as": {
            "name": _as.get("name", "None"),
            "number": _as.get("asn", "None"),
            "description": _as.get("description", "None"),
            "location": _as.get("country_code", "None"),
            "prefix": _as.get("bgp_prefix", "None")
        },
        "location": {
            **raw.get("location", {})
        },
        "ports": [service["port"] for service in raw.get("services", [])]
    }


def censys_extract_service(service: Dict) -> Dict:
    """
    Extracts relevant information from a service object/dict.

    :param service: Censys Search 2.0 service dictionary
    """
    port = service["port"]
    s_common = {}
    if "http" in service:
        s_common.update({"http": censys_extract_http_service(service)})
    if "tls" in service:
        s_common.update({"tls": censys_extract_tls_service(service)})
    return {
        port: s_common
    }


def censys_extract_http_service(service: Dict) -> Dict:
    """Extracts relevant http service fields.

    :param service: Censys Search 2.0 service dictionary
    """
    s_http = {}
    res = service.get("http", {}).get("response", None)
    if not res:
        return {}

    headers = res.get("headers", None)
    if headers:
        s_http["headers"] = {}
    for k, v in headers.items():
        if k == "_encoding":
            continue

        s_http["headers"][k.lower()] = v[0]
    s_http["content"] = {
        "html": res.get("body"),
        "hash": {
            "shodan": mmh3_hash(res.get("body", None) or ""),
            "sha256": sha256_from_body_string(res.get("body", None) or ""),
            "censys": res.get("body_hash", None)
        }
    }
    return s_http


def censys_extract_tls_service(service: Dict) -> Dict:
    """Extracts relevant tls service fields.

    :param service: Censys Search 2.0 service dictionary
    """
    s_tls = {}
    cert = service.get("tls", {}).get("certificates", {}).get("leaf_data", None)
    c_issuer = cert.get("issuer", None) or dict()
    c_subject = cert.get("subject", None) or dict()
    common_name = [c_subject.get("common_name", [])]
    common_name.extend(cert.get("names", []))
    if len(common_name) == 0:
        common_name = None
    if not cert:
        return {}

    s_tls["certificate"] = {
        "issuer_dn": cert.get("issuer_dn", None),
        "subject_dn": cert.get("subject_dn", None),
        "issuer": {
            "common_name": _first_or_none(c_issuer["common_name"]),
            # MISSING! "country": _first_or_none(c_issuer["country"]),
            "locality": _first_or_none(c_issuer["locality"]),
            "province": _first_or_none(c_issuer["province"]),
            "organization": _first_or_none(c_issuer["organization"]),
            "organizational_unit": _first_or_none(c_issuer["organizational_unit"]),
            # MISSING! "email_address": _first_or_none(c_issuer["email_address"]),
        },
        "subject": {
            "common_name": common_name,
            # MISSING! "country": _first_or_none(c_issuer["country"]),
            "locality": _first_or_none(c_subject["locality"]),
            "province": _first_or_none(c_subject["province"]),
            "organization": _first_or_none(c_subject["organization"]),
            "organizational_unit": _first_or_none(c_subject["organizational_unit"]),
            # MISSING! "email_address": _first_or_none(c_subject["email_address"]),
        },
        "fingerprint": {
            "sha256": cert.get("fingerprint", None)
        }
    }
    return s_tls


def _first_or_none(l: List) -> Any:
    """Returns first element of list or none, if list is empty."""
    if not l:
        return None
    if len(l) > 0:
        return l[0]
    return None
