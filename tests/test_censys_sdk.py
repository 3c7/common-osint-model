import json
from datetime import datetime
from common_osint_model import Host, Service
from censys_platform.utils import unmarshal_json
from censys_platform.models import HostAsset, Service as CensysService

from mocks import CENSYS_HOST_JSON_PLATFORM

def test_host_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for Basic Host
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert com_host.ip == censys_host.resource.ip

def test_asn_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for ASN
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert com_host.autonomous_system.number == 20115

def test_domain_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    
    # Actual test for Forward Domain
    assert len(com_host.domains[0].domain) > 0
    assert com_host.domains[0].domain == censys_host.resource.dns.forward_dns.get(com_host.domains[0].domain).name

    # Actual test for Forward Domaims
    assert len(com_host.domains[1].domain) > 0
    assert com_host.domains[1].domain in censys_host.resource.dns.reverse_dns.names

def test_host_services_mock_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    assert censys_host.resource.ip == "27.33.219.14"
    
    # Actual test for service
    com_host = Host.from_censys(censys_host)
    assert type(com_host) is Host
    assert len(com_host.ports) == 1
    assert 7547 in com_host.ports
    assert len(com_host.services) == 1
    assert com_host.services[0].protocol == "CWMP"
    assert com_host.services[0].sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert com_host.services[0].timestamp == datetime.fromisoformat("2025-03-06T19:03:55Z")
    assert com_host.services[0].source == "censys"

def test_service_success():
    # Make sure that import works
    censys_host = unmarshal_json(json.dumps(CENSYS_HOST_JSON_PLATFORM), HostAsset)
    assert type(censys_host) is HostAsset
    censys_services = censys_host.resource.services
    assert len(censys_services) == 1
    censys_service = censys_services[0]
    assert type(censys_service) is CensysService
    
    # Actual test for service
    com_service = Service.from_censys(censys_service)
    assert com_service.port == 7547
    assert com_service.protocol == "CWMP"
    assert com_service.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert com_service.timestamp == datetime.fromisoformat("2025-03-06T19:03:55Z")
    assert com_service.source == "censys"