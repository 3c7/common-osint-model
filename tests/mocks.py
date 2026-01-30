# Censys examples based on https://github.com/censys/censys-python/blob/main/tests/search/v2/test_hosts.py
CENSYS_HOST_JSON = {
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
