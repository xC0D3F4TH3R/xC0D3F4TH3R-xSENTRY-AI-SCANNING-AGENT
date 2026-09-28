import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentryscan.result_parser import ScanReport, HostResult, PortResult
from sentryscan.agent import plan_chain
from sentryscan.tools.native_probes import HTTPHeaderAdapter, TLSInspectAdapter, AnonymousFTPAdapter


def _report_with_ports(*port_service):
    host = HostResult(address="10.0.0.5", state="up")
    for port, service in port_service:
        host.ports.append(PortResult(port=port, protocol="tcp", state="open", service=service))
    return ScanReport(raw_command=["nmap"], hosts=[host])


def test_web_port_triggers_http_and_no_tls():
    report = _report_with_ports((80, "http"))
    plan = plan_chain(report, deep=False)
    names = {a.name for _, _, _, a in plan}
    assert "http-headers" in names
    assert "tls-inspect" not in names


def test_https_port_triggers_tls():
    report = _report_with_ports((443, "https"))
    plan = plan_chain(report, deep=False)
    names = {a.name for _, _, _, a in plan}
    assert "tls-inspect" in names


def test_ftp_port_triggers_anon_check():
    report = _report_with_ports((21, "ftp"))
    plan = plan_chain(report, deep=False)
    names = {a.name for _, _, _, a in plan}
    assert "ftp-anon-check" in names


def test_deep_mode_adds_gobuster_only_when_requested():
    report = _report_with_ports((80, "http"))
    plan_shallow = plan_chain(report, deep=False)
    plan_deep = plan_chain(report, deep=True)
    names_shallow = {a.name for _, _, _, a in plan_shallow}
    names_deep = {a.name for _, _, _, a in plan_deep}
    assert "gobuster" not in names_shallow
    assert "gobuster" in names_deep


def test_closed_ports_produce_no_plan():
    host = HostResult(address="10.0.0.5", state="up")
    host.ports.append(PortResult(port=80, protocol="tcp", state="closed", service="http"))
    report = ScanReport(raw_command=["nmap"], hosts=[host])
    plan = plan_chain(report, deep=False)
    assert plan == []


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
