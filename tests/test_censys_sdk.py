import json
from common_osint_model import Host
from censys_platform.utils import unmarshal_json
from censys_platform.models import HostAsset

from mocks import CENSYS_HOST_JSON_PLATFORM

def test_censys_sdk_host_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for Basic Host
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert com_host.ip == censys_host.resource.ip

def test_censys_sdk_asn_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for ASN
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert com_host.autonomous_system.number == censys_host.resource.autonomous_system.asn

def test_censys_sdk_domain_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for Domain
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert len(com_host.domains[0].domain) > 0
    assert com_host.domains[0].domain == censys_host.resource.dns.forward_dns.get(com_host.domains[0].domain).name