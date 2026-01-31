# Censys examples based on https://github.com/censys/censys-python/blob/main/tests/search/v2/test_hosts.py
CENSYS_HOST_JSON_LEGACY = {
    "services": [
        {
            "transport_protocol": "UDP",
            "truncated": False,
            "service_name": "DNS",
            "_decoded": "dns",
            "source_ip": "167.248.133.40",
            "extended_service_name": "DNS",
            "observed_at": "2021-04-01T13:40:03.755876935Z",
            "dns": {"server_type": "FORWARDING"},
            "perspective_id": "PERSPECTIVE_NTT",
            "port": 53,
            "software": [],
        }
    ],
    "ip": "8.8.8.8",
    "location_updated_at": "2021-03-30T14:53:12.980328Z",
    "location": {
        "country": "United States",
        "coordinates": {"latitude": 37.751, "longitude": -97.822},
        "registered_country": "United States",
        "registered_country_code": "US",
        "postal_code": "",
        "country_code": "US",
        "timezone": "America/Chicago",
        "continent": "North America",
    },
    "last_updated_at": "2021-04-01T14:10:10.712Z",
}

# Censys Examples based on https://docs.censys.com/reference/get-started
CENSYS_HOST_JSON_PLATFORM = {
    "resource": {
        "ip": "27.33.219.14",
        "location": {
        "continent": "North America",
        "country": "United States",
        "country_code": "US",
        "city": "Mount Pleasant",
        "postal_code": "48858",
        "timezone": "America/Detroit",
        "province": "Michigan",
        "coordinates": {
            "latitude": 43.59781,
            "longitude": -84.76751
        }
        },
        "autonomous_system": {
        "asn": 20115,
        "description": "ACME-20115",
        "bgp_prefix": "47.33.192.0/19",
        "name": "ACME-20115",
        "country_code": "US"
        },
        "whois": {
        "network": {
            "handle": "AC04",
            "name": "Acme",
            "cidrs": [
            "47.32.0.0/12",
            "47.48.0.0/14"
            ],
            "created": "2014-12-23T00:00:00Z",
            "updated": "2014-12-23T00:00:00Z",
            "allocation_type": "ALLOCATION"
        },
        "organization": {
            "handle": "CC04",
            "name": "Acme",
            "street": "6175 S. Willow Dr",
            "city": "Greenwood Village",
            "state": "CO",
            "postal_code": "80111",
            "country": "US",
            "abuse_contacts": [
            {
                "handle": "ABUSE19-ARIN",
                "name": "Abuse",
                "email": "abuse@acme.com"
            }
            ],
            "admin_contacts": [
            {
                "handle": "IPADD1-VRIN",
                "name": "IPAddressing",
                "email": "PublicIPAddressing@acme.com"
            }
            ],
            "tech_contacts": [
            {
                "handle": "IPADD1-VRIN",
                "name": "IPAddressing",
                "email": "PublicIPAddressing@acme.com"
            }
            ]
        }
        },
        "services": [
        {
            "port": 7547,
            "protocol": "CWMP",
            "transport_protocol": "tcp",
            "ip": "47.24.210.14",
            "scan_time": "2025-03-06T19:03:55Z",
            "banner_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "cwmp": {
            "auth": [
                "Digest realm=\"Sagemcom TR-069\", qop=\"auth,auth-int\", nonce=<REDACTED>, opaque=\"ddb504c1\""
            ],
            "server": "gSOAP/2.7"
            }
        }
        ],
        "service_count": 1,
        "dns": {
        "reverse_dns": {
            "resolve_time": "2025-02-13T14:02:41Z",
            "names": [
            "syn-047-033-210-014.res.acme.com"
            ]
        },
        "names": [
            "syn-047-033-210-014.res.spectrum.com"
        ],
        "forward_dns": {
            "syn-047-033-210-014.res.acme.com": {
            "resolve_time": "2025-02-27T20:21:52Z",
            "name": "syn-047-033-210-014.res.acme.com",
            "record_type": "a"
            }
        }
        }
    },
    "extensions": {}
    }