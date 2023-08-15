# Common OSINT Model

**Note:** This is work in progress and probably only covers my specific use case. If you find bugs or know how to
enhance this project, please open an issue or - even better - create a pull request. The presented data model is
evolving continuously. Therefore, it is recommended to use it in your project with a fixed version constraint (e.g. 
`common-osint-model==0.4.1`) and take a look at what has changed here before updating `common-osint-model` as a
dependency.

This project aims to create an easy to use data model as well as implement converters for commonly used sources. As my
use case often includes HTTP(S), TLS and SSH only, data delivered for other protocols by the given sources might not
show up correctly or just by the banner included. Because the available scanning services use different hashes for 
different purposes, one might be not able to search across services with the available data. This model automatically 
calculates hashes wherever raw data is available.

## Todos
- [ ] Implement additional SSH ciphers for Censys data. Currently only RSA is supported. Censys do not provide raw 
 public keys in their data, but the public key can be built through the components given.

## The data model

**Note:** The model was restructured with version 0.4.0. The previously provieded functionality can still be used,
however, the old model is considered deprecated and is not further developed.

Since version 0.4.0 the model changed. During refactoring, all model components were implemented as
[pydantic](https://pydantic-docs.helpmanual.io/) classes in order to provide a more "pythonic" way of interacting with
the data. Also, this enables an easy to read and structurized view of the model itself. Please take a look at the model
files available in [models](common_osint_model/models) for more details. The model starts with a host which has an IP,
domains pointing to it and provides multiple services:

```python
class Host:
    ip: str
    autonomous_system: Optional[AutonomousSystem]
    services: List[Service]
    first_seen: Optional[datetime] = datetime.utcnow()
    last_seen: Optional[datetime] = datetime.utcnow()
    domains: Optional[List[Domain]]
```

A service listens on a specific port, has various components (currently only HTTP, TLS and SSH implemented), a banner
and a source (e.g. Shodan) as well as some timestamps.

```python
class Service:
    port: int
    banner: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
    first_seen: Optional[datetime] = datetime.utcnow()
    last_seen: Optional[datetime] = datetime.utcnow()
    timestamp: Optional[datetime]
    http: Optional[HTTPComponent]
    tls: Optional[TLSComponent]
    ssh: Optional[SSHComponent]
    source: str
```

The further model classes are designed in a similar way, please have a look at the
[source files](common_osint_model/models).

## How to use

### Installation

```bash
pip install common-osint-model
```

### Convert all the things

```python
# Post-v0.4.0 (Pydantic model)
import shodan
from common_osint_model import Host

shodan_client = shodan.Shodan("My API key")
raw_shodan_response = shodan_client.host("140.82.121.4")
host = Host.from_shodan(raw_shodan_response)
# Similarly:
# Host.from_censys(raw_censys_response)
# Host.from_binaryedge(raw_binaryedge_response)
# Make sure to only pass results for *one* host. Currently there is no functionality provided to wrap around different 
# return types, such as lists of hosts from a query. You need to loop through them yourself.
print(f"Got {host.ip}.")
print(f"Providing {len(host.services)} services.")

for idx, service in enumerate(host.services):
    print(f"Banner for Service {idx + 1}:")
    print(f"\t{service.banner}")
    print(f"\tMD5: {service.md5}")
    print(f"\tSHA1: {service.sha1}")
    print(f"\tSHA256: {service.sha256}")
    print(f"\tMurmur: {service.murmur}")

print("Exporting data as flattened json blob for further use, e.g. Elasticsearch indexing...")
print(host.flattened_json())
```

### Example output

```python
import shodan
from common_osint_model import Host

shodan_client = shodan.Shodan("My API key")
raw_shodan_response = shodan_client.host("140.82.121.4")
host = Host.from_shodan(raw_shodan_response)
print(f"Host: {host.ip}")
print(f"AS: {host.autonomous_system.dict(exclude_none=True)}")

for service in host.services:
    print(f"Service: {service}")

print("--- flattened JSON dump ---")
print(host.flattened_json())
```

```
Host: 140.82.121.4
AS: {'number': 36459, 'name': 'GitHub, Inc.', 'country': 'DE', 'source': 'shodan'}
Service: port=443 banner='HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: https://github.com/\r\n\r\n' md5='d402a6212741f3690b4fa1e46d9bd8b6' sha1='a24eb4ba0332776d38050a7b41d0366742dbf262' sha256='5fbe0315395986d131e4948888987319e88e3e1da6c5460e8a0bf8b7a1e639f0' murmur='-1655207803' first_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656097) last_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656099) timestamp=datetime.datetime(2021, 8, 16, 20, 42, 40, 325940) http=HTTPComponent(headers={'Content-Length': '0', 'Location': 'https://github.com/'}, content=HTTPComponentContent(raw='', length=0, md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709', sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', murmur='0', favicon=None, robots_txt=None, security_txt=None)) tls=TLSComponent(certificate=TLSComponentCertificate(issuer=TLSComponentCertificateEntity(dn='C=US, O=DigiCert, Inc., CN=DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1', country='US', state=None, locality=None, organization='DigiCert, Inc.', organizational_unit=None, common_name='DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1', email_address=None), subject=TLSComponentCertificateEntity(dn='C=US, ST=California, L=San Francisco, O=GitHub, Inc., CN=github.com', country='US', state='California', locality='San Francisco', organization='GitHub, Inc.', organizational_unit=None, common_name='github.com', email_address=None), issued=datetime.datetime(2021, 3, 25, 0, 0), expires=datetime.datetime(2022, 3, 30, 23, 59, 59), expired=False, alternative_names=['www.github.com', 'github.com'], pem='-----BEGIN CERTIFICATE-----\nMIIFBjCCBK2gAwIBAgIQDovzdw2S0Zbwu2H5PEFmvjAKBggqhkjOPQQDAjBnMQsw\nCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xPzA9BgNVBAMTNkRp\nZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIFRMUyBIeWJyaWQgRUNDIFNIQTI1NiAyMDIw\nIENBMTAeFw0yMTAzMjUwMDAwMDBaFw0yMjAzMzAyMzU5NTlaMGYxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv\nMRUwEwYDVQQKEwxHaXRIdWIsIEluYy4xEzARBgNVBAMTCmdpdGh1Yi5jb20wWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAASt9vd1sdNJVApdEHG93CUGSyIcoiNOn6H+\nudCMvTm8DCPHz5GmkFrYRasDE77BI3q5xMidR/aW4Ll2a1A2ZvcNo4IDOjCCAzYw\nHwYDVR0jBBgwFoAUUGGmoNI1xBEqII0fD6xC8M0pz0swHQYDVR0OBBYEFCexfp+7\nJplQ2PPDU1v+MRawux5yMCUGA1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRo\ndWIuY29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB\nBQUHAwIwgbEGA1UdHwSBqTCBpjBRoE+gTYZLaHR0cDovL2NybDMuZGlnaWNlcnQu\nY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZVRMU0h5YnJpZEVDQ1NIQTI1NjIwMjBD\nQTEuY3JsMFGgT6BNhktodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRI\naWdoQXNzdXJhbmNlVExTSHlicmlkRUNDU0hBMjU2MjAyMENBMS5jcmwwPgYDVR0g\nBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2Vy\ndC5jb20vQ1BTMIGSBggrBgEFBQcBAQSBhTCBgjAkBggrBgEFBQcwAYYYaHR0cDov\nL29jc3AuZGlnaWNlcnQuY29tMFoGCCsGAQUFBzAChk5odHRwOi8vY2FjZXJ0cy5k\naWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlVExTSHlicmlkRUNDU0hB\nMjU2MjAyMENBMS5jcnQwDAYDVR0TAQH/BAIwADCCAQUGCisGAQQB1nkCBAIEgfYE\ngfMA8QB2ACl5vvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAABeGq/vRoA\nAAQDAEcwRQIhAJ7miER//DRFnDJNn6uUhgau3WMt4vVfY5dGigulOdjXAiBIVCfR\nxjK1v4F31+sVaKzyyO7JAa0fzDQM7skQckSYWQB3ACJFRQdZVSRWlj+hL/H3bYbg\nIyZjrcBLf13Gg1xu4g8CAAABeGq/vTkAAAQDAEgwRgIhAJgAEkoJQRivBlwo7x67\n3oVsf1ip096WshZqmRCuL/JpAiEA3cX4rb3waLDLq4C48NSoUmcw56PwO/m2uwnQ\nprb+yh0wCgYIKoZIzj0EAwIDRwAwRAIgK+Kv7G+/KkWkNZg3PcQFp866Z7G6soxo\na4etSZ+SRlYCIBSiXS20Wc+yjD111nPzvQUCfsP4+DKZ3K+2GKsERD6d\n-----END CERTIFICATE-----\n', md5='a07ee2076a6e392e1e96481e99ba094b', sha1='8463b3a92912ccfd1d314705989bec139937d0d7', sha256='0ae384bfd4dde9d13e50c5857c05a442c93f8e01445ee4b34540d22bd1e37f1b', murmur=None)) ssh=None source='shodan'

Service: port=80 banner='HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: https://140.82.121.4/\r\n\r\n' md5='86c9c13165fff2c41db667dd1f6500db' sha1='8ecee0314c63c092d449b0d37d00f0ff62448dd1' sha256='715fd6cec44f12bb5e59f57bf9a1691708a5a2d2ef253399358ac3ff88f47781' murmur='1256792822' first_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656097) last_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656099) timestamp=datetime.datetime(2021, 8, 16, 20, 42, 38, 12570) http=HTTPComponent(headers={'Content-Length': '0', 'Location': 'https://140.82.121.4/'}, content=HTTPComponentContent(raw='', length=0, md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709', sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', murmur='0', favicon=None, robots_txt=None, security_txt=None)) tls=None ssh=None source='shodan'

Service: port=9418 banner='0020ERR \n  Repository not found.' md5='fc79d10176a28462bc071909fb99d59e' sha1='0df752dd6b3d3a461f30691ff89ee67ef3dd21b1' sha256='5f355dafa7999d06265bb17e949b76eab283e9966ef8e27908c4e1058a891121' murmur='-1636861384' first_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656097) last_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656099) timestamp=datetime.datetime(2021, 8, 12, 2, 10, 13, 136596) http=None tls=None ssh=None source='shodan'

Service: port=22 banner='SSH-2.0-babeld-968490c5\nKey type: ssh-rsa\nKey: AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH\nkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY\nP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW\nf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG\nHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\nFingerprint: 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48\n\nKex Algorithms:\n\tcurve25519-sha256\n\tcurve25519-sha256@libssh.org\n\tecdh-sha2-nistp256\n\tecdh-sha2-nistp384\n\tecdh-sha2-nistp521\n\tdiffie-hellman-group-exchange-sha256\n\nServer Host Key Algorithms:\n\trsa-sha2-512\n\trsa-sha2-256\n\tssh-rsa\n\tssh-dss\n\nEncryption Algorithms:\n\tchacha20-poly1305@openssh.com\n\taes256-gcm@openssh.com\n\taes128-gcm@openssh.com\n\taes256-ctr\n\taes192-ctr\n\taes128-ctr\n\taes256-cbc\n\taes192-cbc\n\taes128-cbc\n\nMAC Algorithms:\n\thmac-sha2-512-etm@openssh.com\n\thmac-sha2-256-etm@openssh.com\n\thmac-sha2-512\n\thmac-sha2-256\n\thmac-sha1-etm@openssh.com\n\thmac-sha1\n\nCompression Algorithms:\n\tnone\n\n' md5='d652c84a47553c66047cf67e51f1345a' sha1='679cc04ce70413f639351328bb2f0a70545d0cb6' sha256='2431ffe5d8acbb77b6db91ee84f75baa0422d56947e0b85331dde2560e5454d5' murmur='1023136053' first_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656097) last_seen=datetime.datetime(2021, 8, 20, 16, 10, 27, 656099) timestamp=datetime.datetime(2021, 8, 3, 21, 10, 29, 568093) http=None tls=None ssh=SSHComponent(algorithms=SSHComponentAlgorithms(encryption=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr', 'aes256-cbc', 'aes192-cbc', 'aes128-cbc'], key_exchange=['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256'], mac=['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'hmac-sha1-etm@openssh.com', 'hmac-sha1'], key_algorithms=['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'], compression=['none']), key=SSHComponentKey(raw='AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH\nkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY\nP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW\nf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG\nHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\n', type='ssh-rsa', md5='1627aca576282d36631b564debdfa648', sha1='bf6b6825d2977c511a475bbefb88aad54a92ac73', sha256='9d385b83a9175292561a5ec4d4818e0aca51a264f17420112ef88ac3a139498f', murmur='-388505952')) source='shodan'

--- flattened JSON dump ---
{
  "443.port": 443,
  "443.banner": "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: https://github.com/\r\n\r\n",
  "443.md5": "d402a6212741f3690b4fa1e46d9bd8b6",
  "443.sha1": "a24eb4ba0332776d38050a7b41d0366742dbf262",
  "443.sha256": "5fbe0315395986d131e4948888987319e88e3e1da6c5460e8a0bf8b7a1e639f0",
  "443.murmur": "-1655207803",
  "443.first_seen": "2021-08-20T16:10:27.656097",
  "443.last_seen": "2021-08-20T16:10:27.656099",
  "443.timestamp": "2021-08-16T20:42:40.325940",
  "443.http.headers.Content-Length": "0",
  "443.http.headers.Location": "https://github.com/",
  "443.http.content.raw": "",
  "443.http.content.length": 0,
  "443.http.content.md5": "d41d8cd98f00b204e9800998ecf8427e",
  "443.http.content.sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "443.http.content.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "443.http.content.murmur": "0",
  "443.tls.certificate.issuer.dn": "C=US, O=DigiCert, Inc., CN=DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1",
  "443.tls.certificate.issuer.country": "US",
  "443.tls.certificate.issuer.organization": "DigiCert, Inc.",
  "443.tls.certificate.issuer.common_name": "DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1",
  "443.tls.certificate.subject.dn": "C=US, ST=California, L=San Francisco, O=GitHub, Inc., CN=github.com",
  "443.tls.certificate.subject.country": "US",
  "443.tls.certificate.subject.state": "California",
  "443.tls.certificate.subject.locality": "San Francisco",
  "443.tls.certificate.subject.organization": "GitHub, Inc.",
  "443.tls.certificate.subject.common_name": "github.com",
  "443.tls.certificate.issued": "2021-03-25T00:00:00",
  "443.tls.certificate.expires": "2022-03-30T23:59:59",
  "443.tls.certificate.expired": false,
  "443.tls.certificate.alternative_names": [
    "www.github.com",
    "github.com"
  ],
  "443.tls.certificate.pem": "-----BEGIN CERTIFICATE-----\nMIIFBjCCBK2gAwIBAgIQDovzdw2S0Zbwu2H5PEFmvjAKBggqhkjOPQQDAjBnMQsw\nCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xPzA9BgNVBAMTNkRp\nZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIFRMUyBIeWJyaWQgRUNDIFNIQTI1NiAyMDIw\nIENBMTAeFw0yMTAzMjUwMDAwMDBaFw0yMjAzMzAyMzU5NTlaMGYxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv\nMRUwEwYDVQQKEwxHaXRIdWIsIEluYy4xEzARBgNVBAMTCmdpdGh1Yi5jb20wWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAASt9vd1sdNJVApdEHG93CUGSyIcoiNOn6H+\nudCMvTm8DCPHz5GmkFrYRasDE77BI3q5xMidR/aW4Ll2a1A2ZvcNo4IDOjCCAzYw\nHwYDVR0jBBgwFoAUUGGmoNI1xBEqII0fD6xC8M0pz0swHQYDVR0OBBYEFCexfp+7\nJplQ2PPDU1v+MRawux5yMCUGA1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRo\ndWIuY29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB\nBQUHAwIwgbEGA1UdHwSBqTCBpjBRoE+gTYZLaHR0cDovL2NybDMuZGlnaWNlcnQu\nY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZVRMU0h5YnJpZEVDQ1NIQTI1NjIwMjBD\nQTEuY3JsMFGgT6BNhktodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRI\naWdoQXNzdXJhbmNlVExTSHlicmlkRUNDU0hBMjU2MjAyMENBMS5jcmwwPgYDVR0g\nBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2Vy\ndC5jb20vQ1BTMIGSBggrBgEFBQcBAQSBhTCBgjAkBggrBgEFBQcwAYYYaHR0cDov\nL29jc3AuZGlnaWNlcnQuY29tMFoGCCsGAQUFBzAChk5odHRwOi8vY2FjZXJ0cy5k\naWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlVExTSHlicmlkRUNDU0hB\nMjU2MjAyMENBMS5jcnQwDAYDVR0TAQH/BAIwADCCAQUGCisGAQQB1nkCBAIEgfYE\ngfMA8QB2ACl5vvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAABeGq/vRoA\nAAQDAEcwRQIhAJ7miER//DRFnDJNn6uUhgau3WMt4vVfY5dGigulOdjXAiBIVCfR\nxjK1v4F31+sVaKzyyO7JAa0fzDQM7skQckSYWQB3ACJFRQdZVSRWlj+hL/H3bYbg\nIyZjrcBLf13Gg1xu4g8CAAABeGq/vTkAAAQDAEgwRgIhAJgAEkoJQRivBlwo7x67\n3oVsf1ip096WshZqmRCuL/JpAiEA3cX4rb3waLDLq4C48NSoUmcw56PwO/m2uwnQ\nprb+yh0wCgYIKoZIzj0EAwIDRwAwRAIgK+Kv7G+/KkWkNZg3PcQFp866Z7G6soxo\na4etSZ+SRlYCIBSiXS20Wc+yjD111nPzvQUCfsP4+DKZ3K+2GKsERD6d\n-----END CERTIFICATE-----\n",
  "443.tls.certificate.md5": "a07ee2076a6e392e1e96481e99ba094b",
  "443.tls.certificate.sha1": "8463b3a92912ccfd1d314705989bec139937d0d7",
  "443.tls.certificate.sha256": "0ae384bfd4dde9d13e50c5857c05a442c93f8e01445ee4b34540d22bd1e37f1b",
  "443.source": "shodan",
  "80.port": 80,
  "80.banner": "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: https://140.82.121.4/\r\n\r\n",
  "80.md5": "86c9c13165fff2c41db667dd1f6500db",
  "80.sha1": "8ecee0314c63c092d449b0d37d00f0ff62448dd1",
  "80.sha256": "715fd6cec44f12bb5e59f57bf9a1691708a5a2d2ef253399358ac3ff88f47781",
  "80.murmur": "1256792822",
  "80.first_seen": "2021-08-20T16:10:27.656097",
  "80.last_seen": "2021-08-20T16:10:27.656099",
  "80.timestamp": "2021-08-16T20:42:38.012570",
  "80.http.headers.Content-Length": "0",
  "80.http.headers.Location": "https://140.82.121.4/",
  "80.http.content.raw": "",
  "80.http.content.length": 0,
  "80.http.content.md5": "d41d8cd98f00b204e9800998ecf8427e",
  "80.http.content.sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "80.http.content.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "80.http.content.murmur": "0",
  "80.source": "shodan",
  "9418.port": 9418,
  "9418.banner": "0020ERR \n  Repository not found.",
  "9418.md5": "fc79d10176a28462bc071909fb99d59e",
  "9418.sha1": "0df752dd6b3d3a461f30691ff89ee67ef3dd21b1",
  "9418.sha256": "5f355dafa7999d06265bb17e949b76eab283e9966ef8e27908c4e1058a891121",
  "9418.murmur": "-1636861384",
  "9418.first_seen": "2021-08-20T16:10:27.656097",
  "9418.last_seen": "2021-08-20T16:10:27.656099",
  "9418.timestamp": "2021-08-12T02:10:13.136596",
  "9418.source": "shodan",
  "22.port": 22,
  "22.banner": "SSH-2.0-babeld-968490c5\nKey type: ssh-rsa\nKey: AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH\nkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY\nP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW\nf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG\nHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\nFingerprint: 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48\n\nKex Algorithms:\n\tcurve25519-sha256\n\tcurve25519-sha256@libssh.org\n\tecdh-sha2-nistp256\n\tecdh-sha2-nistp384\n\tecdh-sha2-nistp521\n\tdiffie-hellman-group-exchange-sha256\n\nServer Host Key Algorithms:\n\trsa-sha2-512\n\trsa-sha2-256\n\tssh-rsa\n\tssh-dss\n\nEncryption Algorithms:\n\tchacha20-poly1305@openssh.com\n\taes256-gcm@openssh.com\n\taes128-gcm@openssh.com\n\taes256-ctr\n\taes192-ctr\n\taes128-ctr\n\taes256-cbc\n\taes192-cbc\n\taes128-cbc\n\nMAC Algorithms:\n\thmac-sha2-512-etm@openssh.com\n\thmac-sha2-256-etm@openssh.com\n\thmac-sha2-512\n\thmac-sha2-256\n\thmac-sha1-etm@openssh.com\n\thmac-sha1\n\nCompression Algorithms:\n\tnone\n\n",
  "22.md5": "d652c84a47553c66047cf67e51f1345a",
  "22.sha1": "679cc04ce70413f639351328bb2f0a70545d0cb6",
  "22.sha256": "2431ffe5d8acbb77b6db91ee84f75baa0422d56947e0b85331dde2560e5454d5",
  "22.murmur": "1023136053",
  "22.first_seen": "2021-08-20T16:10:27.656097",
  "22.last_seen": "2021-08-20T16:10:27.656099",
  "22.timestamp": "2021-08-03T21:10:29.568093",
  "22.ssh.algorithms.encryption": [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc"
  ],
  "22.ssh.algorithms.key_exchange": [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256"
  ],
  "22.ssh.algorithms.mac": [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1"
  ],
  "22.ssh.algorithms.key_algorithms": [
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss"
  ],
  "22.ssh.algorithms.compression": [
    "none"
  ],
  "22.ssh.key.raw": "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH\nkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY\nP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW\nf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG\nHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\n",
  "22.ssh.key.type": "ssh-rsa",
  "22.ssh.key.md5": "1627aca576282d36631b564debdfa648",
  "22.ssh.key.sha1": "bf6b6825d2977c511a475bbefb88aad54a92ac73",
  "22.ssh.key.sha256": "9d385b83a9175292561a5ec4d4818e0aca51a264f17420112ef88ac3a139498f",
  "22.ssh.key.murmur": "-388505952",
  "22.source": "shodan"
}
```