import pathlib
import json
import pytest
from common_osint_model import Host

def test_quad_one_success():
    file:pathlib.Path = pathlib.Path.cwd() / "test_data" / "1.1.1.1_censys.json"
    with open(file, "r") as censys_file:
        host = Host.from_censys(json.loads(censys_file.read()))
        assert host.ip == "1.1.1.1"

def test_quad_nine_success():
    file:pathlib.Path = pathlib.Path.cwd() / "test_data" / "9.9.9.9_censys_v2.json"
    with open(file, "r") as censys_file:
        host = Host.from_censys(json.loads(censys_file.read()))
        assert host.ip == "9.9.9.9"

def test_quad_one_fail_be():
    file:pathlib.Path = pathlib.Path.cwd() / "test_data" / "1.1.1.1_binaryedge.json"
    with open(file, "r") as binaryedge_file:
        # This should fail, because we cannot parse binaryedge output with censys parser
        with pytest.raises(KeyError):
            Host.from_censys(json.loads(binaryedge_file.read()))

def test_quad_one_fail_sh():
    file:pathlib.Path = pathlib.Path.cwd() / "test_data" / "1.1.1.1_shodan.json"
    with open(file, "r") as shodan_file:
        # This should fail, because we cannot parse shodan output with censys parser
        with pytest.raises(KeyError):
            Host.from_censys(json.loads(shodan_file.read()))