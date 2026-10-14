import json

from common_osint_model import Host


def test_modat_basic_host_data():
    json_data = """{
      "ip": "45.32.77.95",
      "geo": {
        "city_name": "Los Angeles",
        "country_name": "United States",
        "country_iso_code": "US",
        "continent_code": "NA",
        "accuracy_radius": 20,
        "location": [
          -118.2414,
          34.0609
        ]
      },
      "asn": {
        "number": 20473,
        "org": "The Constant Company, LLC",
        "netblock": "45.32.0.0/16"
      },
      "fqdns": [
        "bstough.com"
      ],
      "rdns": [
        "45.32.77.95.vultrusercontent.com"
      ],
      "is_anycast": false,
      "tags": [
        "C2",
        "PQC SSH",
        "Malicious"
      ],
      "cves": [
        {
          "id": "CVE-2023-31018",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-13367",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47331",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2022-28656",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47333",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2018-16845",
          "cvss": 6.1,
          "is_kev": false
        },
        {
          "id": "CVE-2019-9511",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-2084",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0090",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2020-11935",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-28652",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-5493",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-3888",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2016-1247",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2021-3975",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-51384",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-1804",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-48208",
          "cvss": 8.6,
          "is_kev": false
        },
        {
          "id": "CVE-2022-1184",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2021-40524",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2025-32728",
          "cvss": 3.8,
          "is_kev": false
        },
        {
          "id": "CVE-2019-9516",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0093",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-39176",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2020-27352",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2022-1055",
          "cvss": 8.6,
          "is_kev": false
        },
        {
          "id": "CVE-2026-59999",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47330",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2023-1380",
          "cvss": 7.1,
          "is_kev": false
        },
        {
          "id": "CVE-2022-41742",
          "cvss": 7.1,
          "is_kev": false
        },
        {
          "id": "CVE-2026-31431",
          "cvss": 7.8,
          "is_kev": true
        },
        {
          "id": "CVE-2023-31022",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-60002",
          "cvss": 9.4,
          "is_kev": false
        },
        {
          "id": "CVE-2023-44487",
          "cvss": 7.5,
          "is_kev": true
        },
        {
          "id": "CVE-2018-16843",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-31021",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2020-35359",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-28531",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-35788",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-73283",
          "cvss": 2.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47329",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47337",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2022-28655",
          "cvss": 7.1,
          "is_kev": false
        },
        {
          "id": "CVE-2026-59995",
          "cvss": 5.4,
          "is_kev": false
        },
        {
          "id": "CVE-2022-1242",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0085",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2021-3899",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2016-0747",
          "cvss": 5.3,
          "is_kev": false
        },
        {
          "id": "CVE-2023-4911",
          "cvss": 7.8,
          "is_kev": true
        },
        {
          "id": "CVE-2022-28654",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-0386",
          "cvss": 7.8,
          "is_kev": true
        },
        {
          "id": "CVE-2024-0092",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-28657",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2021-3905",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47336",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2022-41222",
          "cvss": 7,
          "is_kev": false
        },
        {
          "id": "CVE-2023-0179",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-3567",
          "cvss": 7.1,
          "is_kev": false
        },
        {
          "id": "CVE-2024-6773",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-5616",
          "cvss": 4.9,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47327",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47334",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-35388",
          "cvss": 2.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-41741",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2025-26465",
          "cvss": 6.8,
          "is_kev": false
        },
        {
          "id": "CVE-2022-44544",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2019-9513",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-59996",
          "cvss": 5.4,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0115",
          "cvss": 6.1,
          "is_kev": false
        },
        {
          "id": "CVE-2026-55653",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-27776",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2025-26466",
          "cvss": 5.9,
          "is_kev": false
        },
        {
          "id": "CVE-2022-2586",
          "cvss": 7.8,
          "is_kev": true
        },
        {
          "id": "CVE-2026-73281",
          "cvss": 3.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-40617",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2020-9365",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-55654",
          "cvss": 3.7,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47335",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-51385",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2018-16844",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2025-32463",
          "cvss": 7.8,
          "is_kev": true
        },
        {
          "id": "CVE-2024-36390",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-44216",
          "cvss": 5.3,
          "is_kev": false
        },
        {
          "id": "CVE-2022-29581",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2021-3618",
          "cvss": 7.4,
          "is_kev": false
        },
        {
          "id": "CVE-2024-5290",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2021-23017",
          "cvss": 7.7,
          "is_kev": false
        },
        {
          "id": "CVE-2026-60000",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47328",
          "cvss": 6.1,
          "is_kev": false
        },
        {
          "id": "CVE-2017-7529",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-23238",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2025-33208",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-36388",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-73282",
          "cvss": 4.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-35414",
          "cvss": 8.1,
          "is_kev": false
        },
        {
          "id": "CVE-2023-3389",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-36389",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2016-0742",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-6387",
          "cvss": 8.1,
          "is_kev": false
        },
        {
          "id": "CVE-2026-35387",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-1523",
          "cvss": 10,
          "is_kev": false
        },
        {
          "id": "CVE-2023-48795",
          "cvss": 5.9,
          "is_kev": false
        },
        {
          "id": "CVE-2022-40277",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-45866",
          "cvss": 6.3,
          "is_kev": false
        },
        {
          "id": "CVE-2022-28658",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-40283",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47326",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2025-5054",
          "cvss": 4.7,
          "is_kev": false
        },
        {
          "id": "CVE-2022-34918",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-3777",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-36391",
          "cvss": 7.4,
          "is_kev": false
        },
        {
          "id": "CVE-2022-2602",
          "cvss": 7,
          "is_kev": false
        },
        {
          "id": "CVE-2026-3497",
          "cvss": 6.9,
          "is_kev": false
        },
        {
          "id": "CVE-2026-60001",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-3328",
          "cvss": 7,
          "is_kev": false
        },
        {
          "id": "CVE-2022-2585",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-32629",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2016-4450",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-31026",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-59998",
          "cvss": 6.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-47332",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2022-1736",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0091",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2022-2588",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2017-12170",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-13476",
          "cvss": 7.3,
          "is_kev": false
        },
        {
          "id": "CVE-2020-9274",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0084",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2022-39177",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-1326",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2024-11586",
          "cvss": 4,
          "is_kev": false
        },
        {
          "id": "CVE-2023-5536",
          "cvss": 6.4,
          "is_kev": false
        },
        {
          "id": "CVE-2025-23419",
          "cvss": 5.3,
          "is_kev": false
        },
        {
          "id": "CVE-2023-1786",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2019-20372",
          "cvss": 5.3,
          "is_kev": false
        },
        {
          "id": "CVE-2026-59997",
          "cvss": 5.4,
          "is_kev": false
        },
        {
          "id": "CVE-2023-38408",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-2612",
          "cvss": 4.7,
          "is_kev": false
        },
        {
          "id": "CVE-2016-0746",
          "cvss": 9.8,
          "is_kev": false
        },
        {
          "id": "CVE-2019-20176",
          "cvss": 7.5,
          "is_kev": false
        },
        {
          "id": "CVE-2023-1032",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2026-55655",
          "cvss": 6.1,
          "is_kev": false
        },
        {
          "id": "CVE-2023-3297",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-106587",
          "cvss": 3.3,
          "is_kev": false
        },
        {
          "id": "CVE-2024-0086",
          "cvss": 5.5,
          "is_kev": false
        },
        {
          "id": "CVE-2021-3600",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2025-6966",
          "cvss": 6.9,
          "is_kev": false
        },
        {
          "id": "CVE-2023-2640",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2026-35385",
          "cvss": 8.1,
          "is_kev": false
        },
        {
          "id": "CVE-2024-36392",
          "cvss": 6.1,
          "is_kev": false
        },
        {
          "id": "CVE-2023-24492",
          "cvss": 8.8,
          "is_kev": false
        },
        {
          "id": "CVE-2023-31248",
          "cvss": 7.8,
          "is_kev": false
        },
        {
          "id": "CVE-2017-20005",
          "cvss": 9.8,
          "is_kev": false
        }
      ],
      "services": [
        {
          "transport": "tcp",
          "port": 22,
          "ports": [
            22
          ],
          "last_scanned_port": 22,
          "protocol": "ssh",
          "scanned_at": "2026-10-11T07:41:57Z",
          "discovered_at": null,
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 888,
          "ports": [
            888
          ],
          "last_scanned_port": 888,
          "protocol": "http",
          "scanned_at": "2026-10-10T01:23:42Z",
          "discovered_at": null,
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 8080,
          "ports": [
            8080
          ],
          "last_scanned_port": 8080,
          "protocol": "http",
          "scanned_at": "2026-10-07T10:51:54Z",
          "discovered_at": "2026-08-14T07:50:08Z",
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 28355,
          "ports": [
            28355
          ],
          "last_scanned_port": 28355,
          "protocol": "http",
          "scanned_at": "2026-10-11T06:39:20Z",
          "discovered_at": "2026-07-19T17:19:27Z",
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 8998,
          "ports": [
            8998
          ],
          "last_scanned_port": 8998,
          "protocol": "http",
          "scanned_at": "2026-10-06T16:47:23Z",
          "discovered_at": "2026-09-14T02:20:21Z",
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 80,
          "ports": [
            80
          ],
          "last_scanned_port": 80,
          "protocol": "http",
          "scanned_at": "2026-10-11T10:01:51Z",
          "discovered_at": null,
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 3306,
          "ports": [
            3306
          ],
          "last_scanned_port": 3306,
          "protocol": "mysql",
          "scanned_at": "2026-10-11T06:44:56Z",
          "discovered_at": null,
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 8682,
          "ports": [
            8682
          ],
          "last_scanned_port": 8682,
          "protocol": "http",
          "scanned_at": "2026-10-08T04:59:25Z",
          "discovered_at": "2026-09-06T04:06:03Z",
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 21,
          "ports": [
            21
          ],
          "last_scanned_port": 21,
          "protocol": "ftp",
          "scanned_at": "2026-10-11T05:31:08Z",
          "discovered_at": null,
          "is_match": false
        },
        {
          "transport": "tcp",
          "port": 8981,
          "ports": [
            8981
          ],
          "last_scanned_port": 8981,
          "protocol": "http",
          "scanned_at": "2026-10-08T08:44:37Z",
          "discovered_at": "2026-08-31T21:25:54Z",
          "is_match": true
        }
      ]
    }
"""
    data = json.loads(json_data)
    host = Host.from_modat(data)
    assert host.ip == "45.32.77.95"
    assert len(host.services) == 10
    assert len(host.ports) == 10
    assert host.autonomous_system.name == "The Constant Company, LLC"
