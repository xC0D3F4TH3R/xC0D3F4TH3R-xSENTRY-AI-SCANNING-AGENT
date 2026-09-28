import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentryscan.intent_parser import parse_intent_rule_based, intent_to_nmap_args
from sentryscan.result_parser import HostResult, PortResult
from sentryscan.risk_rules import evaluate_host


def test_target_extraction_ip():
    intent = parse_intent_rule_based("scan 192.168.1.10 for open ports")
    assert intent.target == "192.168.1.10"


def test_target_extraction_cidr():
    intent = parse_intent_rule_based("check my network 10.0.0.0/24 for web servers")
    assert intent.target == "10.0.0.0/24"
    assert intent.port_mode == "web"


def test_intensity_quiet():
    intent = parse_intent_rule_based("do a stealthy quiet scan of 10.0.0.5")
    assert intent.intensity == "quiet"


def test_intensity_aggressive():
    intent = parse_intent_rule_based("run a deep aggressive scan on 10.0.0.5 with OS detection")
    assert intent.intensity == "aggressive"
    assert intent.os_detection is True


def test_custom_ports():
    intent = parse_intent_rule_based("scan 10.0.0.5 on ports 22,80,443")
    assert intent.port_mode == "custom"
    assert intent.custom_ports == "22,80,443"


def test_nmap_args_contain_target_flag_not_target():
    intent = parse_intent_rule_based("quick scan of 10.0.0.5")
    args = intent_to_nmap_args(intent)
    assert "10.0.0.5" not in args  # target passed separately by scanner, never embedded in flags
    assert "-oX" in args


def test_risk_flags_flag_smb():
    host = HostResult(address="10.0.0.5", ports=[PortResult(port=445, protocol="tcp", state="open", service="smb")])
    flags = evaluate_host(host)
    assert any(f.port == 445 for f in flags)
    assert flags[0].severity == "high"


if __name__ == "__main__":
    import inspect
    fails = 0
    mod = sys.modules[__name__]
    for name, fn in inspect.getmembers(mod, inspect.isfunction):
        if name.startswith("test_"):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                fails += 1
                print(f"FAIL {name}: {e}")
    sys.exit(1 if fails else 0)
