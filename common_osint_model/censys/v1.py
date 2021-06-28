from common_osint_model.utils import flatten, unflatten, common_model_cn_extraction, sha256_from_body_string, \
    list_cleanup
from DateTime import DateTime
from datetime import datetime
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
    for protocol in raw.get("protocols", []):
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
        "ip": raw["ip"],  # Program should fail if IP is not given
        "as": {
            "number": _as.get("asn", None),
            "name": _as.get("name", None),
            "location": _as.get("country_code", None),
            "prefix": _as.get("routed_prefix", None),
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
    timestamp = raw.get("updated_at", None)
    service = {
        "timestamp": int(DateTime(timestamp)) if timestamp else None,
        "timestamp_readable": DateTime(timestamp).ISO8601() if timestamp else None,
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
            "html": s.get("body", None),
            "hash": {
                "shodan": mmh3_hash(s.get("body", None) or ""),
                "sha256": s.get("body_sha256", None) or sha256_from_body_string("")
            },
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


def from_censys_certificates(raw: dict) -> dict:
    """
    Converts a censys certificates dictionary to the common model format
    :param raw: Censys certificates dict
    :return: Common model dict
    """
    flattened = False
    for k in raw.keys():
        if "." in k:
            flattened = True
            break
        elif k == "parsed":
            break

    if flattened:
        raw = unflatten(raw)

    return dict(censys_certificates_parsed_extraction(raw["parsed"]))


def from_censys_certificates_flattened(raw: dict) -> dict:
    """
    Converts a censys certificates dictionary to the flattened common model format
    :param raw: Censys certificates dict
    :return: Common model dict
    """
    return flatten(from_censys_certificates(raw))


def censys_certificates_parsed_extraction(parsed: dict) -> dict:
    """
    Extracts the parsed certificate data
    :param p: "Parsed" dictionary of censys data
    :return: Dictionary with parsed certificate data in common model format
    """
    issuer = {}
    subject = {}
    fingerprint = {}
    validity = {}
    for issuer_key, issuer_item in parsed.get("issuer", {}).items():
        issuer.update({
            issuer_key: issuer_item
        })
    for subject_key, subject_item in parsed.get("subject", {}).items():
        subject.update({
            subject_key: subject_item
        })
    for fp_key, fp_item in parsed.items():
        if "fingerprint_" not in fp_key:
            continue
        fingerprint.update({
            fp_key.replace("fingerprint_", ""): fp_item
        })

    for extension, content in parsed.get("extensions", {}).items():
        if extension == "subject_alt_name":
            cn = subject.get("common_name", None)
            altnames = content.get("dns_names", [])
            if cn and cn in altnames or not cn:
                subject["common_name"] = altnames
            elif cn and cn not in altnames:
                if isinstance(cn, str):
                    altnames.append(cn)
                elif isinstance(cn, list):
                    for name in cn:
                        if name not in altnames:
                            altnames.append(name)
                subject["common_name"] = altnames

    start = datetime.strptime(parsed["validity"]["start"], "%Y-%m-%dT%H:%M:%SZ")
    end = datetime.strptime(parsed["validity"]["end"], "%Y-%m-%dT%H:%M:%SZ")
    validity = {
        "start": int(start.timestamp()),
        "start_readable": start.isoformat(),
        "end": int(end.timestamp()),
        "end_readable": end.isoformat(),
        "length": int((end - start).total_seconds())
    }

    p = {
        "issuer": issuer,
        "issuer_dn": parsed.get("issuer_dn", None),
        "subject": subject,
        "subject_dn": parsed.get("subject_dn", None),
        "fingerprint": fingerprint,
        "validity": validity,
        "serial_number": parsed.get("serial_number", None)
    }
    return list_cleanup(p)
