from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import psutil

from netwatch.checks import CHECKS, add_findings
from netwatch.config import load_settings
from netwatch.models import Device, Finding, NetworkConfig, ScanResult, Severity
from netwatch.scanner import (
    TOP_100_PORTS,
    _arp_discover,
    _sanitize_banner,
    _vendor_for_mac,
    discover_devices,
)
from netwatch.storage import (
    annotate_baseline_status,
    diff_against_baseline,
    get_scan,
    list_scans,
    save_baseline,
    save_scan,
)


def _mock_module_platform(monkeypatch, module_name: str, platform: str) -> None:
    from importlib import import_module
    from types import SimpleNamespace

    module = import_module(module_name)
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform=platform))


def test_mocking_module_platform_does_not_change_process_platform(monkeypatch) -> None:
    actual_platform = sys.platform

    _mock_module_platform(monkeypatch, "netwatch.scanner", "win32")

    assert sys.platform == actual_platform


def test_help_output_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "netwatch", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


def test_baseline_and_devices_work(tmp_path: Path) -> None:
    db_path = tmp_path / "netwatch.db"
    env = os.environ.copy()
    env["NETWATCH_DB_PATH"] = str(db_path)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    try:
        scan = subprocess.run(
            [
                sys.executable,
                "-m",
                "netwatch",
                "scan",
                "--cidr",
                "127.0.0.1/32",
                "--ports",
                str(port),
                "--yes",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=10,
        )
        assert scan.returncode == 0
        scan_data = json.loads(scan.stdout)
        assert scan_data["devices"][0]["open_ports"] == [port]
        assert scan_data["devices"][0]["last_seen"]

        baseline = subprocess.run(
            [
                sys.executable,
                "-m",
                "netwatch",
                "baseline",
                "--cidr",
                "127.0.0.1/32",
                "--ports",
                str(port),
                "--yes",
                "--trust-all",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=10,
        )
        assert baseline.returncode == 0
        assert "lack a MAC address" not in baseline.stderr
        after_baseline = subprocess.run(
            [
                sys.executable,
                "-m",
                "netwatch",
                "scan",
                "--cidr",
                "127.0.0.1/32",
                "--ports",
                str(port),
                "--yes",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=10,
        )
        assert after_baseline.returncode == 0
        baseline_scan_data = json.loads(after_baseline.stdout)
        assert baseline_scan_data["scan"]["baseline_exists"] is False
        assert baseline_scan_data["devices"][0]["trusted"] is None
    finally:
        server.close()

    devices = subprocess.run(
        [sys.executable, "-m", "netwatch", "devices"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert devices.returncode == 0
    assert "127.0.0.1" in devices.stdout


def test_no_argument_launch_opens_interactive_menu() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "netwatch"],
        input="6\n0\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "netwatch> " in result.stdout
    assert "Implemented checks:" in result.stdout
    assert "Goodbye." in result.stdout


def test_public_ranges_are_rejected_by_default() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "netwatch",
            "scan",
            "--cidr",
            "8.8.8.8/32",
            "--ports",
            "80",
            "--yes",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 3
    assert "Refusing to scan a public network" in result.stderr


def test_on_link_guard_accepts_hosts_inside_local_subnet_and_refuses_others(
    monkeypatch,
) -> None:
    from types import SimpleNamespace

    from netwatch.scanner import NetworkScopeError, _validate_on_link

    monkeypatch.setattr(
        "netwatch.scanner.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                ),
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="169.254.1.10",
                    netmask="255.255.0.0",
                ),
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="127.0.0.1",
                    netmask="255.0.0.0",
                ),
            ]
        },
    )
    for target in ("192.168.1.1/32", "192.168.1.0/24"):
        _validate_on_link(ipaddress.ip_network(target))
    for target in ("192.168.2.0/24", "10.99.0.0/24", "192.168.0.0/16"):
        try:
            _validate_on_link(ipaddress.ip_network(target))
            raise AssertionError(f"{target} should be refused")
        except NetworkScopeError as exc:
            assert f"This machine is not on {ipaddress.ip_network(target)}" in str(exc)


def test_tunnel_routes_are_rejected_before_scanning(monkeypatch) -> None:
    from netwatch.scanner import NetworkScopeError, _validate_route_for_network

    monkeypatch.setattr(
        "netwatch.scanner._list_ip_routes",
        lambda: [{"destination": "0.0.0.0/0", "interface": "xray_tun"}],
    )
    try:
        _validate_route_for_network(ipaddress.ip_network("192.168.1.0/24"))
        raise AssertionError("Expected tunnel route to be rejected")
    except NetworkScopeError as exc:
        assert "xray_tun" in str(exc)


def test_config_file_support_reads_expected_dns_and_ignore_rules(
    tmp_path: Path, monkeypatch
) -> None:
    config_dir = tmp_path / ".config" / "netwatch"
    config_dir.mkdir(parents=True)
    (config_dir / "config.toml").write_text(
        """
[network]
expected_dns = ["192.168.1.1", "1.1.1.1"]

[checks]
skip = ["plain_http"]

[ignore]
findings = [{ check = "telnet_open", target = "192.168.1.20" }]

[report]
fail_on = "MEDIUM"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    settings = load_settings(NetworkConfig())
    assert settings.expected_dns == ["192.168.1.1", "1.1.1.1"]
    assert settings.skip == ["plain_http"]
    assert settings.ignore_findings == [
        {"check": "telnet_open", "target": "192.168.1.20"}
    ]
    assert settings.fail_on == "MEDIUM"


def test_ignored_findings_are_removed_from_scan_results() -> None:
    result = ScanResult(devices=[Device(ip="192.168.1.20", open_ports=[23])])
    add_findings(
        result,
        only=["telnet_open"],
        ignore=[{"check": "telnet_open", "target": "192.168.1.20"}],
    )
    assert result.findings == []


def test_top100_port_set_contains_100_ports() -> None:
    assert len(TOP_100_PORTS) == 100
    assert {21, 23, 80, 445, 554, 1883, 3389}.issubset(TOP_100_PORTS)


def test_service_checks_explain_reachable_risky_services() -> None:
    result = ScanResult(
        devices=[Device(ip="192.168.1.20", open_ports=[23, 445, 443])],
    )
    add_findings(result, only=["telnet_open", "smb_exposed"])
    assert [finding.name for finding in result.findings] == [
        "telnet_open",
        "smb_exposed",
    ]
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[1].severity is Severity.LOW
    assert "plaintext" in result.findings[0].recommendation
    assert "does not prove" in result.findings[0].description


def test_smb_severity_is_medium_outside_private_ranges() -> None:
    result = ScanResult(devices=[Device(ip="8.8.8.8", open_ports=[445])])
    add_findings(result, only=["smb_exposed"])
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.MEDIUM


def test_terminal_summary_preserves_recommendation_spacing(capsys) -> None:
    from netwatch.reporting import print_scan_summary

    print_scan_summary(
        ScanResult(
            devices=[Device(ip="192.168.1.1")],
            findings=[
                Finding(
                    name="plain_http",
                    title="Unencrypted HTTP",
                    description="HTTP is reachable.",
                    severity=Severity.LOW,
                    recommendation=(
                        "Avoid entering passwords. If it is device administration, use HTTPS if available."
                    ),
                )
            ],
        ),
        no_color=True,
    )
    output = capsys.readouterr().out
    assert "If it is device administration" in output


def test_local_machine_is_tagged_and_has_no_service_exposure_findings(
    monkeypatch, capsys
) -> None:
    from types import SimpleNamespace

    from netwatch.checks import RouterUPnPCheck
    from netwatch.reporting import print_scan_summary
    from netwatch.storage import _device_payload

    monkeypatch.setattr(
        "netwatch.scanner._validate_route_for_network", lambda *_args: None
    )
    monkeypatch.setattr("netwatch.scanner._neighbor_macs", dict)
    monkeypatch.setattr(
        "netwatch.scanner._arp_discover",
        lambda *_args: {"192.168.1.10": "00:11:22:33:44:55"},
    )
    monkeypatch.setattr(
        "netwatch.scanner.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                ),
                SimpleNamespace(family=socket.AF_INET6, address="fe80::1"),
            ]
        },
    )
    monkeypatch.setattr("netwatch.scanner._hostname", lambda _ip: "local-host")
    monkeypatch.setattr(
        "netwatch.scanner._vendor_for_mac", lambda _mac: "Example Vendor"
    )

    async def scan_host(_ip, _ports, _timeout, _port_semaphore, _host_semaphore):
        return [445], {}

    monkeypatch.setattr("netwatch.scanner._scan_host", scan_host)
    result = discover_devices(NetworkConfig(cidr="192.168.1.0/24", ports="445"))
    assert len(result.devices) == 1
    assert result.devices[0].is_local is True
    assert _device_payload(result.devices[0])["is_local"] is True

    add_findings(result, only=["smb_exposed"])
    assert result.findings == []
    print_scan_summary(result, no_color=True)
    assert "This machine" in capsys.readouterr().out
    assert RouterUPnPCheck().run(result.devices[0]) == []


def test_windows_arp_output_parses_hyphenated_macs(monkeypatch) -> None:
    from netwatch.scanner import _neighbor_macs

    output = (
        "Interface: 192.168.56.1 --- 0xd\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.56.255        ff-ff-ff-ff-ff-ff     static\n"
        "  224.0.0.2             01-00-5e-00-00-02     static\n"
        "Interface: 192.168.1.10 --- 0x1a\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           00-0a-3b-f0-00-00     dynamic\n"
        "  192.168.1.11          5a-2f-46-91-f0-b8     dynamic\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    )

    class Completed:
        returncode = 0
        stdout = output

    _mock_module_platform(monkeypatch, "netwatch.scanner", "win32")
    monkeypatch.setattr(
        "netwatch.scanner.subprocess.run",
        lambda command, **_kwargs: Completed(),
    )
    assert _neighbor_macs() == {
        "192.168.1.1": "00:0a:3b:f0:00:00",
        "192.168.1.11": "5a:2f:46:91:f0:b8",
    }


def test_windows_neighbor_cache_is_scoped_and_filters_broadcast_multicast(
    monkeypatch,
) -> None:
    output = (
        "Interface: 192.168.1.10 --- 0x1a\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.5           00-11-22-33-44-55     dynamic\n"
        "  192.168.1.255         00-11-22-33-44-66     static\n"
        "  192.168.1.7           ff-ff-ff-ff-ff-ff     static\n"
        "  224.0.0.2             01-00-5e-00-00-02     static\n"
        "  192.168.2.5           00-11-22-33-44-77     dynamic\n"
    )
    calls = []

    class Completed:
        returncode = 0
        stdout = output

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    _mock_module_platform(monkeypatch, "netwatch.scanner", "win32")
    monkeypatch.setattr("netwatch.scanner.subprocess.run", run)

    from netwatch.scanner import _neighbor_macs

    assert _neighbor_macs(ipaddress.ip_network("192.168.1.0/24"), timeout=5) == {
        "192.168.1.5": "00:11:22:33:44:55",
    }
    assert calls == [
        (
            ["arp", "-a"],
            {
                "capture_output": True,
                "text": True,
                "timeout": 5,
                "check": False,
            },
        )
    ]


def test_windows_dynamic_arp_entries_become_devices_for_full_subnet_scan(
    monkeypatch,
) -> None:
    from types import SimpleNamespace

    from netwatch.scanner import discover_devices

    output = (
        "Interface: 192.168.1.10 --- 0x1a\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           00-11-22-33-44-01     dynamic\n"
        "  192.168.1.11          00-11-22-33-44-0b     dynamic\n"
        "  192.168.1.103         00-11-22-33-44-67     dynamic\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
        "  224.0.0.2             01-00-5e-00-00-02     static\n"
        "Interface: 192.168.56.1 --- 0xd\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.50          00-11-22-33-44-32     dynamic\n"
        "  192.168.56.20         00-11-22-33-44-20     dynamic\n"
    )

    class Completed:
        returncode = 0
        stdout = output

    _mock_module_platform(monkeypatch, "netwatch.scanner", "win32")
    monkeypatch.setattr(
        "netwatch.scanner.subprocess.run", lambda *_args, **_kwargs: Completed()
    )
    monkeypatch.setattr(
        "netwatch.scanner._validate_route_for_network", lambda *_args: None
    )
    monkeypatch.setattr("netwatch.scanner._arp_discover", lambda *_args: None)
    monkeypatch.setattr(
        "netwatch.scanner.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                )
            ]
        },
    )
    monkeypatch.setattr("netwatch.scanner._hostname", lambda ip: f"host-{ip}")

    async def no_open_ports(_ip, _ports, _timeout, _port_sem, _host_sem):
        return [], {}

    monkeypatch.setattr("netwatch.scanner._scan_host", no_open_ports)
    result = discover_devices(NetworkConfig(cidr="192.168.1.0/24", ports="80"))
    assert {device.ip: device.mac for device in result.devices} == {
        "192.168.1.1": "00:11:22:33:44:01",
        "192.168.1.11": "00:11:22:33:44:0b",
        "192.168.1.103": "00:11:22:33:44:67",
    }


def test_plain_http_check_requires_an_http_response() -> None:
    result = ScanResult(
        devices=[
            Device(
                ip="192.168.1.20", open_ports=[80], banners={80: "Test service banner"}
            ),
            Device(
                ip="192.168.1.21",
                open_ports=[80],
                banners={80: "HTTP/1.0 200 OK | Server: test"},
            ),
        ],
    )
    add_findings(result, only=["plain_http"])
    assert len(result.findings) == 1
    assert "192.168.1.21" in result.findings[0].title


def test_http_banner_does_not_persist_cookies_or_response_body() -> None:
    banner = _sanitize_banner(
        b"HTTP/1.0 200 OK\r\nServer: home-device\r\nSet-Cookie: secret=value\r\n\r\nprivate body"
    )
    assert banner == "HTTP/1.0 200 OK | Server: home-device"


def test_checks_support_only_and_skip_filters() -> None:
    result = ScanResult(
        devices=[Device(ip="192.168.1.20", open_ports=[23, 445])],
    )
    add_findings(result, only=["telnet_open"])
    assert [finding.name for finding in result.findings] == ["telnet_open"]

    result = ScanResult(
        devices=[Device(ip="192.168.1.20", open_ports=[23, 445])],
    )
    add_findings(result, only=["telnet_open", "smb_exposed"], skip=["telnet_open"])
    assert [finding.name for finding in result.findings] == ["smb_exposed"]
    assert {check.name for check in CHECKS}


def test_check_visibility_records_no_gateway_and_opt_in_checks() -> None:
    result = ScanResult(devices=[Device(ip="192.168.1.20", open_ports=[80])])
    add_findings(result, only=["router_dns", "router_default_creds"])
    assert result.checks_run == []
    assert result.skipped_checks["router_dns"] == "no gateway was identified"
    assert (
        result.skipped_checks["router_default_creds"]
        == "opt-in required: pass --check-creds"
    )
    assert result.findings == []
    assert len(result.not_tested) == 1
    assert result.not_tested[0].name == "router_dns"
    assert "no gateway was identified" in result.not_tested[0].reason


def test_explicit_only_does_not_enable_default_credentials() -> None:
    result = ScanResult(
        devices=[Device(ip="192.168.1.1", is_gateway=True, open_ports=[443])],
    )
    add_findings(result, only=["router_default_creds"], check_creds=False)
    assert result.checks_run == []
    assert result.findings == []
    assert (
        result.skipped_checks["router_default_creds"]
        == "opt-in required: pass --check-creds"
    )


def test_saved_credential_opt_in_is_overridden_without_cli_flag(
    monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    settings = NetworkConfig(only=["router_default_creds"], check_creds=True)
    monkeypatch.setattr("netwatch.cli.load_settings", lambda _config: settings)
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[Device(ip="192.168.1.1", is_gateway=True, open_ports=[443])],
            cidr="192.168.1.0/24",
        ),
    )
    monkeypatch.setattr("netwatch.cli.annotate_baseline_status", lambda _result: False)
    monkeypatch.setattr("netwatch.cli.save_scan", lambda _result: 1)
    monkeypatch.setattr("netwatch.cli.collect_router_fingerprint", lambda _result: None)
    monkeypatch.setattr(
        "netwatch.checks._router_http_opener",
        lambda _context: (_ for _ in ()).throw(
            AssertionError("credential check must remain disabled")
        ),
    )

    assert main(["scan", "--yes"]) == 0
    assert settings.check_creds is False
    assert "opt-in required: pass --check-creds" in capsys.readouterr().out


def test_check_execution_summary_and_html_visibility(capsys) -> None:
    from netwatch.cli import _print_check_execution_summary
    from netwatch.reporting import render_html_report

    result = ScanResult(
        checks_run=["telnet_open", "router_dns"],
        skipped_checks={"router_default_creds": "opt-in required: pass --check-creds"},
    )
    _print_check_execution_summary(result)
    terminal_output = capsys.readouterr().out
    assert "Checks run: 2 | Findings: 0 | Skipped/opt-in:" in terminal_output
    assert (
        "router_default_creds (opt-in required: pass --check-creds)" in terminal_output
    )

    html = render_html_report(
        {
            "id": 1,
            "checks_run": result.checks_run,
            "skipped_checks": result.skipped_checks,
            "devices": [],
            "findings": [],
        },
        {"new": [], "missing": [], "changed": []},
    )
    assert "Checks run" in html
    assert "telnet_open, router_dns" in html
    assert "router_default_creds: opt-in required: pass --check-creds" in html


def test_check_descriptions_and_findings_have_no_joined_words(
    monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers",
        lambda _network=None: ["192.168.1.1"],
    )
    monkeypatch.setattr(
        "netwatch.checks.RouterUPnPCheck.run_with_result",
        lambda _check, device: ([], f"no SSDP response from {device.ip}"),
    )
    text = [check.description for check in CHECKS]
    result = ScanResult(
        devices=[
            Device(
                ip="192.168.1.1",
                is_gateway=True,
                open_ports=[21, 23, 80, 445, 554, 1883, 3389, 8080],
                banners={80: "HTTP/1.1 200 OK", 8080: "HTTP/1.1 200 OK"},
            )
        ]
    )
    add_findings(
        result,
        only=[
            "ftp_open",
            "telnet_open",
            "smb_exposed",
            "rtsp_open",
            "mqtt_open",
            "rdp_open",
            "plain_http",
            "plain_http_alt",
            "router_upnp",
            "router_dns",
        ],
    )
    text.extend(result.check_results)
    for finding in result.findings:
        text.extend(
            (
                finding.title,
                finding.description,
                finding.recommendation,
                *finding.evidence,
            )
        )
    assert not any("isan" in value.casefold() for value in text)
    assert not any("opt-inwith" in value.casefold() for value in text)

    descriptions = {check.name: check.description for check in CHECKS}
    assert "service is an administration page" in descriptions["plain_http"]
    assert (
        "requires explicit --check-creds opt-in" in descriptions["router_default_creds"]
    )
    assert main(["checks"]) == 0
    check_output = capsys.readouterr().out
    assert "isan" not in check_output.casefold()
    assert "opt-inwith" not in check_output.casefold()


def test_router_checks_record_explicit_zero_finding_results(
    monkeypatch, capsys
) -> None:
    from netwatch.cli import _print_check_execution_summary
    from netwatch.reporting import render_html_report

    class NoResponseSocket:
        def __init__(self, *_args):
            pass

        def settimeout(self, _timeout):
            pass

        def sendto(self, _data, _address):
            pass

        def recvfrom(self, _size):
            raise TimeoutError()

        def close(self):
            pass

    monkeypatch.setattr("netwatch.checks.socket.socket", NoResponseSocket)
    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers",
        lambda _network=None: ["192.168.1.1"],
    )
    gateway = Device(ip="192.168.1.1", is_gateway=True)
    result = ScanResult(devices=[gateway])
    add_findings(result, only=["router_upnp", "router_dns"])

    assert result.findings == []
    assert result.check_results[:2] == [
        "router_upnp: no SSDP response from 192.168.1.1 (UPnP may still be enabled; SSDP can be blocked by a firewall)",
        "router_dns: resolvers 192.168.1.1 look expected for gateway 192.168.1.1",
    ]
    assert (
        "router_default_creds: skipped - not selected by --only" in result.check_results
    )
    _print_check_execution_summary(result)
    terminal = capsys.readouterr().out
    assert terminal.count("Checks run:") == 1
    assert (
        "router_upnp: no SSDP response from 192.168.1.1 (UPnP may still be enabled; "
        "SSDP can be blocked by a firewall)"
    ) in terminal
    assert "router_dns: resolvers 192.168.1.1 look expected" in terminal

    html = render_html_report(
        {
            "checks_run": result.checks_run,
            "check_results": result.check_results,
            "skipped_checks": result.skipped_checks,
            "devices": [],
            "findings": [],
        }
    )
    assert (
        "router_upnp: no SSDP response from 192.168.1.1 (UPnP may still be enabled; "
        "SSDP can be blocked by a firewall)"
    ) in html
    assert "router_dns: resolvers 192.168.1.1 look expected" in html


def test_new_device_check_only_flags_devices_after_baseline() -> None:
    check = next(check for check in CHECKS if check.name == "new_device")
    assert check.run(Device(ip="192.168.1.22", trusted=None)) == []
    findings = check.run(Device(ip="192.168.1.22", trusted=False))
    assert findings[0].severity is Severity.HIGH
    assert "does not establish that it is malicious" in findings[0].description


def test_scan_summary_does_not_claim_zero_findings_means_safe(capsys) -> None:
    from netwatch.cli import _print_scan_summary

    _print_scan_summary(
        ScanResult(
            devices=[Device(ip="192.168.1.1", trusted=None, open_ports=[80, 443])],
            findings=[],
            cidr="192.168.1.0/24",
            scanned_ports=[80, 443],
        )
    )
    output = capsys.readouterr().out
    assert "baseline not set" in output
    assert "80 (HTTP)" in output
    assert "Implemented checks did not flag" in output
    assert "not a complete security assessment" in output


def test_baseline_confirmation_is_required(capsys, monkeypatch) -> None:
    from netwatch.cli import _confirm_baseline_devices

    monkeypatch.setattr("builtins.input", lambda _: "n")
    result = ScanResult(devices=[Device(ip="192.168.1.2")])
    assert not _confirm_baseline_devices(result, trust_all=False)
    assert "Devices to include" in capsys.readouterr().out


def test_baseline_refuses_tcp_fallback_without_force(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "refuse-fallback.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[Device(ip="192.168.1.10", mac="00:11:22:33:44:55")],
            discovery_method="tcp_fallback",
        ),
    )
    assert main(["baseline", "--yes", "--trust-all"]) == 3
    assert "TCP fallback" in capsys.readouterr().err


def test_baseline_refuses_missing_macs_without_force(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "refuse-no-mac.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[Device(ip="192.168.1.10")],
            discovery_method="arp",
        ),
    )
    assert main(["baseline", "--yes", "--trust-all"]) == 3
    assert "lack a MAC address" in capsys.readouterr().err


def test_forced_partial_baseline_skips_devices_without_macs(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main
    from netwatch.storage import list_known_devices

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "forced-baseline.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[
                Device(ip="192.168.1.10", mac="00:11:22:33:44:55"),
                Device(ip="192.168.1.11"),
            ],
            discovery_method="tcp_fallback",
        ),
    )
    assert main(["baseline", "--yes", "--trust-all", "--force"]) == 0
    assert (
        "1 device(s) without MAC addresses will not be saved" in capsys.readouterr().err
    )
    rows = list_known_devices()
    assert [row["mac"] for row in rows] == ["00:11:22:33:44:55"]


def test_forced_baseline_with_no_macs_is_refused(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "forced-no-mac.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[Device(ip="192.168.1.11")],
            discovery_method="tcp_fallback",
        ),
    )
    assert main(["baseline", "--yes", "--trust-all", "--force"]) == 3
    assert "never creates IP-based device identities" in capsys.readouterr().err


def test_scan_history_and_trust_are_persisted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "history.db"))
    known = Device(
        ip="192.168.1.5",
        mac="00:11:22:33:44:55",
        hostname="printer",
        open_ports=[80],
    )
    baseline = ScanResult(
        devices=[known],
        findings=[
            Finding(
                name="plain_http",
                title="HTTP",
                description="HTTP",
                severity=Severity.LOW,
            )
        ],
        cidr="192.168.1.0/24",
        scanned_ports=[80],
        discovery_method="arp",
    )
    save_baseline(baseline)

    current = Device(
        ip="192.168.1.5",
        mac="00:11:22:33:44:55",
        hostname="printer",
        open_ports=[],
    )
    scan = ScanResult(devices=[current], cidr="192.168.1.0/24")
    save_scan(scan)
    assert annotate_baseline_status(scan)
    assert current.trusted is True
    assert diff_against_baseline(scan) == {"new": [], "missing": [], "changed": []}

    history = list_scans()
    assert len(history) == 2
    assert history[0]["discovery_method"] == "tcp"
    assert history[1]["finding_count"] == 1
    latest = get_scan()
    assert latest is not None
    assert latest["cidr"] == "192.168.1.0/24"
    assert get_scan(history[1]["id"])["findings"][0]["name"] == "plain_http"


def test_arp_discovery_records_mac_vendor_and_banner(
    monkeypatch,
) -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def serve_banner() -> None:
        connection, _address = server.accept()
        with connection:
            connection.sendall(b"Test service banner\r\n")
            connection.recv(1024)

    thread = threading.Thread(target=serve_banner, daemon=True)
    thread.start()
    monkeypatch.setattr("netwatch.scanner._neighbor_macs", dict)
    monkeypatch.setattr(
        "netwatch.scanner._arp_discover",
        lambda network, interface: {"127.0.0.1": "00:11:22:33:44:55"},
    )
    monkeypatch.setattr(
        "netwatch.scanner._vendor_for_mac", lambda mac: "Example Vendor"
    )
    monkeypatch.setattr("netwatch.scanner._hostname", lambda ip: "localhost")
    try:
        result = discover_devices(
            NetworkConfig(cidr="127.0.0.1/32", ports=str(port), timeout=1)
        )
    finally:
        server.close()
        thread.join(timeout=2)

    assert result.discovery_method == "arp"
    assert len(result.devices) == 1
    device = result.devices[0]
    assert device.mac == "00:11:22:33:44:55"
    assert device.vendor == "Example Vendor"
    assert device.banners[port] == "Test service banner"


def test_arp_reply_parsing_and_offline_oui_lookup(monkeypatch) -> None:
    from scapy.all import ARP

    monkeypatch.setattr(
        "scapy.all.srp",
        lambda *_args, **_kwargs: (
            [(None, ARP(psrc="192.168.1.25", hwsrc="00:11:22:33:44:55"))],
            [],
        ),
    )
    found = _arp_discover(ipaddress.ip_network("192.168.1.0/24"), "test-interface")
    assert found == {"192.168.1.25": "00:11:22:33:44:55"}
    assert _vendor_for_mac("00:11:22:33:44:55")


def test_changed_mac_on_trusted_ip_is_not_silently_trusted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "trust.db"))
    save_baseline(
        ScanResult(
            devices=[
                Device(
                    ip="192.168.1.8",
                    mac="00:11:22:33:44:55",
                    hostname="known-host",
                )
            ]
        )
    )
    changed = ScanResult(
        devices=[
            Device(
                ip="192.168.1.8",
                mac="AA:BB:CC:DD:EE:FF",
                hostname="known-host",
            )
        ]
    )
    assert annotate_baseline_status(changed)
    assert changed.devices[0].trusted is False
    assert diff_against_baseline(changed)["new"] == ["AA:BB:CC:DD:EE:FF"]


def test_private_randomized_mac_is_labeled_in_terminal_and_html(capsys) -> None:
    from netwatch.models import is_locally_administered_mac
    from netwatch.reporting import print_scan_summary, render_html_report

    assert is_locally_administered_mac("5a:2f:46:91:f0:b8")
    assert is_locally_administered_mac("02-11-22-33-44-55")
    assert not is_locally_administered_mac("00:11:22:33:44:55")

    device = Device(ip="192.168.1.11", mac="5a:2f:46:91:f0:b8")
    print_scan_summary(ScanResult(devices=[device]), no_color=True)
    assert "Private/randomized MAC (likely phone or laptop)" in capsys.readouterr().out

    html = render_html_report(
        {
            "devices": [{"ip": device.ip, "mac": device.mac, "open_ports": []}],
            "findings": [],
        },
        {"new": [], "missing": [], "changed": []},
    )
    assert "Private/randomized MAC (likely phone or laptop)" in html
    assert "may reappear as new devices when their MAC address changes" in html


def test_diff_explains_randomized_mac_reappearance(capsys) -> None:
    from netwatch.cli import _print_diff

    _print_diff({"new": [], "missing": [], "changed": []})
    assert (
        "private/randomized MAC addresses may reappear as new devices"
        in capsys.readouterr().out
    )


def test_scan_returns_unknown_device_exit_code(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "exit-code.db"))
    save_baseline(
        ScanResult(
            devices=[
                Device(ip="192.168.1.5", mac="00:11:22:33:44:55"),
            ]
        )
    )
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[
                Device(ip="192.168.1.9", mac="AA:BB:CC:DD:EE:FF", open_ports=[22]),
            ],
            cidr="192.168.1.0/24",
            scanned_ports=[22],
        ),
    )
    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers",
        lambda _network=None: ["192.168.1.1"],
    )
    monkeypatch.setattr("netwatch.checks.RouterUPnPCheck.run", lambda *_args: [])
    assert main(["scan", "--cidr", "192.168.1.0/24", "--ports", "22", "--yes"]) == 2
    output = capsys.readouterr().out
    assert output.count("Checks run:") == 1
    assert "Skipped/opt-in:" in output


def test_report_fail_on_sets_scan_exit_threshold(monkeypatch) -> None:
    from netwatch.cli import _scan_exit_code, main

    settings = NetworkConfig(only=["telnet_open"], fail_on="CRITICAL")
    monkeypatch.setattr("netwatch.cli.load_settings", lambda _config: settings)
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[Device(ip="192.168.1.1", is_gateway=True, open_ports=[23])],
            cidr="192.168.1.0/24",
        ),
    )
    monkeypatch.setattr("netwatch.cli.collect_router_fingerprint", lambda _result: None)
    monkeypatch.setattr("netwatch.cli.annotate_baseline_status", lambda _result: False)
    monkeypatch.setattr("netwatch.cli.save_scan", lambda _result: 1)

    assert main(["scan", "--yes"]) == 0
    settings.fail_on = "HIGH"
    assert main(["scan", "--yes"]) == 1
    assert (
        _scan_exit_code(
            [
                Finding(
                    name="new_device",
                    title="New",
                    description="Unknown device",
                    severity=Severity.HIGH,
                )
            ],
            "CRITICAL",
        )
        == 2
    )


def test_invalid_report_fail_on_is_usage_error(monkeypatch, capsys) -> None:
    from netwatch.cli import main

    monkeypatch.setattr(
        "netwatch.cli.load_settings",
        lambda _config: NetworkConfig(fail_on="SOMETHING"),
    )
    assert main(["scan", "--yes"]) == 3
    assert "Invalid report.fail_on value" in capsys.readouterr().err


def test_tcp_fallback_filters_non_responding_hosts(monkeypatch) -> None:
    # Subnet with 6 usable hosts (.1 to .6)
    config = NetworkConfig(cidr="192.168.1.0/29", ports="80", timeout=0.1)

    monkeypatch.setattr(
        "netwatch.scanner._validate_route_for_network", lambda *_args: None
    )
    monkeypatch.setattr(
        "netwatch.scanner._local_ipv4_networks",
        lambda: {ipaddress.ip_network("192.168.1.0/29")},
    )
    monkeypatch.setattr("netwatch.scanner._arp_discover", lambda _net, _iface: None)

    # Initial ARP cache is empty; the post-sweep cache contains a MAC for .5.
    neighbor_calls = 0

    def mock_neighbors(*, network=None, timeout=3):
        nonlocal neighbor_calls
        neighbor_calls += 1
        if neighbor_calls > 1:
            assert network == ipaddress.ip_network("192.168.1.0/29")
            assert timeout == 5
            return {"192.168.1.5": "00:11:22:33:44:55"}
        return {}

    monkeypatch.setattr("netwatch.scanner._neighbor_macs", mock_neighbors)

    async def mock_scan_host(ip, ports, timeout, port_sem, host_sem):
        if ip == "192.168.1.1":
            return [80], {80: "HTTP/1.1 200 OK"}
        return [], {}

    monkeypatch.setattr("netwatch.scanner._scan_host", mock_scan_host)
    monkeypatch.setattr("netwatch.scanner._hostname", lambda ip: f"host-{ip}")

    result = discover_devices(config)
    assert result.discovery_method == "tcp_sweep+arp_cache"
    # Only 192.168.1.1 (open port) and 192.168.1.5 (neighbor MAC) should be kept
    discovered_ips = [dev.ip for dev in result.devices]
    assert sorted(discovered_ips) == ["192.168.1.1", "192.168.1.5"]
    device_5 = next(d for d in result.devices if d.ip == "192.168.1.5")
    assert device_5.mac == "00:11:22:33:44:55"


def test_tcp_fallback_adds_cached_device_that_did_not_answer_selected_ports(
    monkeypatch,
) -> None:
    config = NetworkConfig(cidr="192.168.1.0/29", ports="80", timeout=0.1)
    monkeypatch.setattr(
        "netwatch.scanner._validate_route_for_network", lambda *_args: None
    )
    monkeypatch.setattr(
        "netwatch.scanner._local_ipv4_networks",
        lambda: {ipaddress.ip_network("192.168.1.0/29")},
    )
    monkeypatch.setattr("netwatch.scanner._arp_discover", lambda *_args: None)
    neighbor_calls = 0

    def mock_neighbors(*, network=None, timeout=3):
        nonlocal neighbor_calls
        neighbor_calls += 1
        if neighbor_calls == 1:
            return {}
        assert network == ipaddress.ip_network("192.168.1.0/29")
        assert timeout == 5
        return {"192.168.1.5": "00:11:22:33:44:55"}

    monkeypatch.setattr("netwatch.scanner._neighbor_macs", mock_neighbors)

    async def mock_scan_host(_ip, _ports, _timeout, _port_sem, _host_sem):
        return [], {}

    monkeypatch.setattr("netwatch.scanner._scan_host", mock_scan_host)
    monkeypatch.setattr("netwatch.scanner._hostname", lambda ip: f"host-{ip}")
    result = discover_devices(config)
    assert result.discovery_method == "tcp_sweep+arp_cache"
    assert len(result.devices) == 1
    assert result.devices[0].ip == "192.168.1.5"
    assert result.devices[0].mac == "00:11:22:33:44:55"
    assert result.devices[0].open_ports == []


def test_loopback_scan_finds_open_port_on_real_listener(monkeypatch) -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("netwatch.scanner._validate_route_for_network", lambda *_args: None)
    monkeypatch.setattr("netwatch.scanner._neighbor_macs", lambda **_kwargs: {})
    monkeypatch.setattr("netwatch.scanner._arp_discover", lambda *_args: None)
    monkeypatch.setattr("netwatch.scanner._hostname", lambda _ip: "localhost")
    try:
        result = discover_devices(
            NetworkConfig(
                cidr="127.0.0.1/32",
                ports=str(server.server_port),
                timeout=0.5,
            )
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert [(device.ip, device.open_ports) for device in result.devices] == [
        ("127.0.0.1", [server.server_port])
    ]


def test_on_link_guard_refuses_unrelated_target_without_saving(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from types import SimpleNamespace

    from netwatch.cli import main
    from netwatch.storage import list_scans

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "off-link.db"))
    monkeypatch.setattr(
        "netwatch.scanner.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                )
            ]
        },
    )
    saved = []
    monkeypatch.setattr("netwatch.cli.save_scan", lambda result: saved.append(result))
    assert (
        main(
            [
                "scan",
                "--cidr",
                "10.99.0.0/24",
                "--ports",
                "80",
                "--yes",
            ]
        )
        == 3
    )
    assert "This machine is not on 10.99.0.0/24. Connect to that network (VPN off) and retry." in capsys.readouterr().err
    assert saved == []
    assert list_scans() == []


def test_local_device_mac_is_read_from_psutil_af_link(monkeypatch) -> None:
    from types import SimpleNamespace

    from netwatch.scanner import discover_devices

    local_ip = "192.168.1.10"
    local_mac = "02:11:22:33:44:55"
    monkeypatch.setattr(
        "netwatch.scanner._validate_route_for_network", lambda *_args: None
    )
    monkeypatch.setattr("netwatch.scanner._neighbor_macs", lambda **_kwargs: {})
    monkeypatch.setattr("netwatch.scanner._arp_discover", lambda *_args: None)
    monkeypatch.setattr(
        "netwatch.scanner.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address=local_ip,
                    netmask="255.255.255.0",
                ),
                SimpleNamespace(family=psutil.AF_LINK, address="02-11-22-33-44-55"),
            ]
        },
    )
    monkeypatch.setattr("netwatch.scanner._hostname", lambda _ip: "local-host")

    async def local_port_open(_ip, _ports, _timeout, _port_sem, _host_sem):
        return ([80], {}) if _ip == local_ip else ([], {})

    monkeypatch.setattr("netwatch.scanner._scan_host", local_port_open)
    result = discover_devices(NetworkConfig(cidr="192.168.1.0/24", ports="80"))
    assert len(result.devices) == 1
    assert result.devices[0].is_local
    assert result.devices[0].mac == local_mac


def test_router_dns_uses_only_adapter_for_scanned_subnet(monkeypatch) -> None:
    from types import SimpleNamespace

    from netwatch.checks import _get_system_dns_resolvers

    _mock_module_platform(monkeypatch, "netwatch.checks", "win32")
    monkeypatch.setattr(
        "netwatch.checks.psutil.net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(family=socket.AF_INET, address="192.168.1.10")
            ],
            "Wi-Fi": [SimpleNamespace(family=socket.AF_INET, address="172.20.10.2")],
            "VirtualBox": [SimpleNamespace(family=socket.AF_INET, address="10.0.2.15")],
        },
    )

    class Completed:
        returncode = 0
        stdout = json.dumps(
            [
                {"InterfaceAlias": "Ethernet", "ServerAddresses": ["192.168.1.1"]},
                {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["80.80.80.80"]},
                {"InterfaceAlias": "VirtualBox", "ServerAddresses": ["1.1.1.1"]},
            ]
        )

    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    monkeypatch.setattr("netwatch.checks.subprocess.run", run)
    assert _get_system_dns_resolvers("192.168.1.0/24") == ["192.168.1.1"]
    assert calls[0][0][0] == "powershell"


def test_not_tested_results_are_not_findings_or_score_penalties() -> None:
    from netwatch.cli import _scan_exit_code
    from netwatch.reporting import report_summary, render_html_report

    result = ScanResult(devices=[Device(ip="192.168.1.20")])
    add_findings(result, only=["router_dns"])
    assert result.findings == []
    assert len(result.not_tested) == 1
    assert _scan_exit_code(result.findings, "INFO") == 0
    saved = {
        "devices": [{"ip": "192.168.1.20"}],
        "findings": [],
        "not_tested": [
            {
                "name": result.not_tested[0].name,
                "reason": result.not_tested[0].reason,
            }
        ],
    }
    summary = report_summary(saved)
    assert summary["finding_count"] == 0
    assert summary["score"] == 100
    assert summary["not_tested_count"] == 1
    html = render_html_report(saved)
    assert "<h2>Not tested</h2>" in html
    assert "Not tested: router_dns" in html


def test_discovery_coverage_explains_selected_scope_and_missed_hosts(capsys) -> None:
    from netwatch.reporting import print_scan_summary

    print_scan_summary(
        ScanResult(
            cidr="192.168.1.0/24",
            scanned_ports=[80],
            discovery_method="tcp_sweep+arp_cache",
        ),
        no_color=True,
    )
    output = capsys.readouterr().out
    assert "selected ports and the operating system's ARP cache" in output
    assert "sleeping or firewalled devices can still be missed" in output


def test_telnet_banner_sanitization() -> None:
    # IAC commands followed by real greeting
    data_with_text = b"\xff\xfb\x01\xff\xfd\x01\r\nWelcome to OpenWrt\r\n"
    assert _sanitize_banner(data_with_text) == "Welcome to OpenWrt"

    # Only IAC command bytes
    pure_iac = b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18"
    assert _sanitize_banner(pure_iac) is None

    # IAC commands followed by orphan punctuation
    iac_with_punctuation = b"\xff\xfb\x01#'"
    assert _sanitize_banner(iac_with_punctuation) is None


def test_gateway_fingerprint_is_read_only_and_bounded(monkeypatch) -> None:
    from typing import ClassVar

    from netwatch.scanner import collect_router_fingerprint

    requests = []

    class Response:
        headers: ClassVar[dict[str, str]] = {"Server": "NETGEAR HTTP Server"}

        def read(self, size):
            assert size == 65536
            return b"<html><title>NETGEAR Router</title></html>"

        def close(self):
            self.closed = True

    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return Response()

    monkeypatch.setattr(
        "netwatch.scanner.urllib.request.build_opener", lambda *handlers: Opener()
    )

    class TelnetSocket:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

        def settimeout(self, timeout):
            assert timeout == 1.0

        def recv(self, size):
            assert size == 512
            return b"\xff\xfb\x01\r\nRouterOS Telnet service\r\n"

    telnet_socket = TelnetSocket()

    def create_connection(address, timeout):
        assert address == ("192.168.1.1", 23)
        assert timeout == 1.0
        return telnet_socket

    monkeypatch.setattr("netwatch.scanner.socket.create_connection", create_connection)
    result = ScanResult(
        devices=[
            Device(
                ip="192.168.1.1",
                is_gateway=True,
                open_ports=[23, 80],
            )
        ]
    )
    collect_router_fingerprint(result)
    fingerprint = result.devices[0].router_fingerprint

    assert fingerprint == {
        "server": "NETGEAR HTTP Server",
        "http_title": "NETGEAR Router",
        "telnet_banner": "RouterOS Telnet service",
    }
    request, timeout = requests[0]
    assert request.get_method() == "GET"
    assert "Authorization" not in request.headers
    assert timeout == 3.0
    assert telnet_socket.closed


def test_gateway_fingerprint_retries_title_read_and_reports_timeout(
    monkeypatch, capsys
) -> None:
    import urllib.error

    from netwatch.reporting import print_scan_summary
    from netwatch.scanner import collect_router_fingerprint

    calls = []
    sleeps = []

    class Response:
        headers = {}

        def read(self, _size):
            return b"<title>4G LTE WiFi Router</title>"

        def close(self):
            pass

    class Opener:
        def open(self, _request, timeout):
            calls.append(timeout)
            if len(calls) == 1:
                raise urllib.error.URLError(TimeoutError("timed out"))
            assert timeout == 3.0
            return Response()

    monkeypatch.setattr(
        "netwatch.scanner.urllib.request.build_opener", lambda *_handlers: Opener()
    )
    monkeypatch.setattr(
        "netwatch.scanner.time.sleep", lambda seconds: sleeps.append(seconds)
    )
    scan = ScanResult(
        devices=[Device(ip="192.168.1.1", is_gateway=True, open_ports=[80, 443])]
    )
    collect_router_fingerprint(scan)
    assert scan.devices[0].router_fingerprint["http_title"] == "4G LTE WiFi Router"
    assert calls == [3.0, 3.0]
    assert sleeps == [1.0]

    class TimeoutOpener:
        def open(self, _request, timeout):
            assert timeout == 3.0
            calls.append(timeout)
            raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(
        "netwatch.scanner.urllib.request.build_opener",
        lambda *_handlers: TimeoutOpener(),
    )
    timed_out = ScanResult(
        devices=[Device(ip="192.168.1.1", is_gateway=True, open_ports=[80, 443])]
    )
    collect_router_fingerprint(timed_out)
    print_scan_summary(timed_out, no_color=True)
    output = capsys.readouterr().out
    assert "Unavailable (timed out)" in output
    assert timed_out.devices[0].router_fingerprint["http_title_error"] == "timed out"
    assert calls[-3:] == [3.0, 3.0, 3.0]
    assert sleeps[-2:] == [1.0, 1.0]
    from netwatch.reporting import render_html_report

    html = render_html_report(
        {
            "devices": [
                {
                    "ip": "192.168.1.1",
                    "is_gateway": True,
                    "router_fingerprint": timed_out.devices[0].router_fingerprint,
                }
            ],
            "findings": [],
        }
    )
    assert "Unavailable (timed out)" in html


def test_missing_npcap_prints_one_plain_fallback_line(monkeypatch, capsys, recwarn) -> None:
    from scapy.error import Scapy_Exception

    from netwatch.scanner import _arp_discover

    def missing_pcap(*_args, **_kwargs):
        raise Scapy_Exception("Npcap is not installed")

    monkeypatch.setattr("scapy.all.srp", missing_pcap)
    assert _arp_discover(ipaddress.ip_network("192.168.1.0/24"), None) is None
    assert (
        capsys.readouterr().out
        == "Npcap not installed: using TCP sweep + ARP cache.\n"
    )
    assert not recwarn


def test_gateway_telnet_fix_text_includes_brand_and_isp_guidance() -> None:
    from netwatch.checks import CHECKS

    telnet_check = next(check for check in CHECKS if check.name == "telnet_open")
    findings = telnet_check.run(
        Device(
            ip="192.168.1.1",
            is_gateway=True,
            open_ports=[23],
            router_fingerprint={"server": "NETGEAR HTTP Server"},
        )
    )
    assert len(findings) == 1
    recommendation = findings[0].recommendation
    assert "fingerprint suggests NETGEAR" in recommendation
    assert "ISP-managed routers may not allow disabling it" in recommendation
    assert "change the admin password" in recommendation
    assert "contact your ISP" in recommendation


def test_router_fingerprint_is_shown_in_terminal_html_and_saved(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    from netwatch.reporting import print_scan_summary, render_html_report
    from netwatch.storage import get_scan

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "fingerprint.db"))
    gateway = Device(
        ip="192.168.1.1",
        is_gateway=True,
        router_fingerprint={
            "http_title": "<Router Control>",
            "server": "NETGEAR",
            "telnet_banner": "RouterOS",
        },
    )
    scan = ScanResult(devices=[gateway])
    print_scan_summary(scan, no_color=True)
    terminal = capsys.readouterr().out
    assert "Router fingerprint" in terminal
    assert "<Router Control>" in terminal

    save_scan(scan)
    saved = get_scan()
    assert saved is not None
    assert saved["devices"][0]["router_fingerprint"] == gateway.router_fingerprint
    html = render_html_report(saved, {"new": [], "missing": [], "changed": []})
    assert "Router fingerprint" in html
    assert "&lt;Router Control&gt;" in html
    assert "NETGEAR" in html
    assert "RouterOS" in html


def test_router_default_creds_skipped_for_non_gateway() -> None:
    from netwatch.checks import RouterDefaultCredsCheck

    check = RouterDefaultCredsCheck(enabled=True)
    non_gw = Device(ip="192.168.1.50", is_gateway=False, open_ports=[80])
    assert check.run(non_gw) == []


def test_router_default_creds_unauthenticated_baseline_200_no_false_positive() -> None:
    import http.server

    class NoAuthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Welcome to unauthenticated page")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), NoAuthHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    from netwatch.checks import RouterDefaultCredsCheck

    try:
        check = RouterDefaultCredsCheck(
            enabled=True, delay_seconds=0, target_ports=[port]
        )
        gw = Device(ip="127.0.0.1", is_gateway=True, open_ports=[port])
        findings = check.run(gw)
        assert len(findings) == 1
        # Must be INFO advisory, NOT a CRITICAL default cred finding!
        assert findings[0].severity is Severity.INFO
        assert (
            "default-login test not supported for this login type" in findings[0].title
        )
        assert "not tested:" in findings[0].description
    finally:
        server.shutdown()
        server.server_close()


def test_router_default_creds_accepts_valid_login_and_never_leaks_secret(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    import base64
    import http.server

    from netwatch.checks import RouterDefaultCredsCheck
    from netwatch.storage import _finding_payload, get_scan

    class BasicAuthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get("Authorization")
            expected = "Basic " + base64.b64encode(b"admin:password").decode("ascii")
            if auth == expected:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Test"')
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), BasicAuthHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        check = RouterDefaultCredsCheck(
            enabled=True, delay_seconds=0, target_ports=[port]
        )
        gw = Device(ip="127.0.0.1", is_gateway=True, open_ports=[port])
        findings = check.run(gw)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.name == "router_default_creds"
        assert "Default router credentials accepted" in finding.title

        # Assert secret string "password" NEVER appears anywhere in finding or serialized payload!
        secret = "password"
        assert secret not in finding.title
        assert secret not in finding.description
        assert secret not in finding.recommendation
        for ev in finding.evidence:
            assert secret not in ev

        payload = _finding_payload(finding)
        serialized = json.dumps(payload)
        assert secret not in serialized
        monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "credential-test.db"))
        save_scan(ScanResult(findings=findings))
        saved = get_scan()
        assert saved is not None
        assert secret not in json.dumps(saved)
        assert secret.encode() not in (tmp_path / "credential-test.db").read_bytes()
        assert secret not in caplog.text
    finally:
        server.shutdown()
        server.server_close()


def test_router_default_creds_aborts_on_lockout_429() -> None:
    import http.server

    from netwatch.checks import RouterDefaultCredsCheck

    request_count = 0

    class RateLimitHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal request_count
            request_count += 1
            if request_count == 1:
                # Baseline: 401 with Basic Auth challenge
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Test"')
                self.end_headers()
            else:
                # First cred attempt triggers 429 Too Many Requests
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests - Lockout")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), RateLimitHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        check = RouterDefaultCredsCheck(
            enabled=True, delay_seconds=0, target_ports=[port]
        )
        gw = Device(ip="127.0.0.1", is_gateway=True, open_ports=[port])
        findings = check.run(gw)
        # Should have stopped after hitting 429 on the very first credential attempt
        assert request_count == 2
        # No creds accepted; the INFO result records why further attempts stopped.
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFO
        assert "lockout" in findings[0].description
    finally:
        server.shutdown()
        server.server_close()


def test_router_dns_severities_and_stubs(monkeypatch) -> None:
    from netwatch.checks import RouterDNSCheck

    # Case 1: Loopback stub (systemd-resolved 127.0.0.53) -> explicit cannot-tell INFO result
    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers", lambda: ["127.0.0.53"]
    )
    gw = Device(ip="192.168.1.1", is_gateway=True)
    loopback_findings = RouterDNSCheck().run(gw)
    assert len(loopback_findings) == 1
    assert loopback_findings[0].severity is Severity.INFO
    assert "upstream resolver cannot be determined" in loopback_findings[0].description

    # Case 2: Private LAN IP & known public resolver -> trusted, no finding
    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers",
        lambda: ["192.168.1.1", "1.1.1.1", "8.8.8.8"],
    )
    assert RouterDNSCheck().run(gw) == []

    # Case 3: Unknown public IP without expected_dns configured -> MEDIUM
    monkeypatch.setattr(
        "netwatch.checks._get_system_dns_resolvers", lambda: ["80.80.80.80"]
    )
    findings_med = RouterDNSCheck().run(gw)
    assert len(findings_med) == 1
    assert findings_med[0].severity is Severity.MEDIUM
    assert "Unrecognized public DNS resolver" in findings_med[0].title
    assert "Verify whether" in findings_med[0].recommendation
    assert "ISP" in findings_med[0].recommendation

    # Case 4: Differs from configured expected_dns -> HIGH
    findings_high = RouterDNSCheck(expected_dns=["1.1.1.1", "9.9.9.9"]).run(gw)
    assert len(findings_high) == 1
    assert findings_high[0].severity is Severity.HIGH
    assert "differs from expected resolvers" in findings_high[0].title

    # Case 5: Non-gateway device -> check skipped
    non_gw = Device(ip="192.168.1.20", is_gateway=False)
    assert RouterDNSCheck().run(non_gw) == []


def test_baseline_and_diff_accept_yes_without_reasking_permission(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "yes-baseline.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[
                Device(ip="192.168.1.5", mac="00:11:22:33:44:55"),
            ],
            cidr="192.168.1.0/24",
            discovery_method="arp",
        ),
    )
    monkeypatch.setattr(
        "netwatch.cli.add_findings",
        lambda result, *_args, **_kwargs: setattr(
            result, "check_results", ["router_dns: example result"]
        ),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: (_ for _ in ()).throw(
            AssertionError("permission prompt should be bypassed with --yes")
        ),
    )
    assert (
        main(
            [
                "baseline",
                "--cidr",
                "192.168.1.0/24",
                "--yes",
                "--trust-all",
                "--only",
                "new_device",
            ]
        )
        == 0
    )
    assert "Check results:" not in capsys.readouterr().out
    assert (
        main(
            [
                "diff",
                "--cidr",
                "192.168.1.0/24",
                "--yes",
                "--only",
                "new_device",
            ]
        )
        == 0
    )
    assert "Check results:" not in capsys.readouterr().out


def test_baseline_mac_identity_matches_across_subnets(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "cross-subnet.db"))
    save_baseline(
        ScanResult(
            devices=[
                Device(ip="192.168.1.1", mac="00:11:22:33:44:55"),
            ],
            cidr="192.168.1.0/24",
        )
    )
    current = ScanResult(
        devices=[Device(ip="192.168.1.1", mac="00:11:22:33:44:55")],
        cidr="192.168.1.1/32",
    )
    assert annotate_baseline_status(current)
    assert current.devices[0].trusted is True


def test_local_missing_mac_does_not_block_baseline(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main
    from netwatch.storage import list_known_devices

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "local-no-mac.db"))
    monkeypatch.setattr(
        "netwatch.cli.discover_devices",
        lambda _settings: ScanResult(
            devices=[
                Device(ip="192.168.1.10", is_local=True),
                Device(ip="192.168.1.1", mac="00:11:22:33:44:55"),
            ],
            cidr="192.168.1.0/24",
            discovery_method="arp",
        ),
    )
    assert (
        main(
            [
                "baseline",
                "--yes",
                "--trust-all",
                "--only",
                "new_device",
            ]
        )
        == 0
    )
    assert "Baseline refused" not in capsys.readouterr().err
    assert [row["mac"] for row in list_known_devices()] == ["00:11:22:33:44:55"]


def test_router_upnp_ssdp_handling(monkeypatch) -> None:

    from netwatch.checks import RouterUPnPCheck

    check = RouterUPnPCheck()

    # 1. Timeout / no response -> no finding
    class TimeoutSocket:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def settimeout(self, timeout):
            assert timeout == 0.5

        def sendto(self, data, address):
            assert address in {
                ("127.0.0.1", 1900),
                ("239.255.255.250", 1900),
            }
            assert b"M-SEARCH * HTTP/1.1" in data

        def recvfrom(self, bufsize):
            raise TimeoutError()

        def close(self):
            self.closed = True

    monkeypatch.setattr("socket.socket", TimeoutSocket)
    assert check.run(Device(ip="127.0.0.1", is_gateway=True)) == []

    # 2. Responding SSDP packet on gateway -> MEDIUM finding
    mock_ssdp_reply = (
        b"HTTP/1.1 200 OK\r\n"
        b"LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n"
        b"SERVER: Linux/2.6 UPnP/1.0 MiniUPnPd/2.0\r\n"
        b"ST: upnp:rootdevice\r\n\r\n"
    )

    class MockSocket:
        def __init__(self, *args, **kwargs):
            self.target_ip = "192.168.1.1"

        def settimeout(self, t):
            assert t == 0.5

        def sendto(self, data, addr):
            assert addr[1] == 1900
            assert addr[0] in {"192.168.1.1", "192.168.1.55", "239.255.255.250"}
            if addr[0] != "239.255.255.250":
                self.target_ip = addr[0]
            assert b"M-SEARCH * HTTP/1.1" in data

        def recvfrom(self, bufsize):
            return mock_ssdp_reply, (self.target_ip, 1900)

        def close(self):
            pass

    monkeypatch.setattr("socket.socket", MockSocket)
    monkeypatch.setattr(
        "netwatch.checks._fetch_igd_description", lambda *_args: None
    )
    gw = Device(ip="192.168.1.1", is_gateway=True)
    findings_gw = check.run(gw)
    assert len(findings_gw) == 1
    assert findings_gw[0].severity is Severity.MEDIUM
    assert "gateway" in findings_gw[0].title.lower()

    # 3. Responding SSDP packet on client device -> LOW finding
    client_dev = Device(ip="192.168.1.55", is_gateway=False)
    findings_client = check.run(client_dev)
    assert len(findings_client) == 1
    assert findings_client[0].severity is Severity.LOW

    # 4. Malformed / binary garbage reply does not crash
    class MalformedSocket(MockSocket):
        def recvfrom(self, bufsize):
            return b"\x00\xff\xfe\x00\x01\x02", ("192.168.1.1", 1900)

    monkeypatch.setattr("socket.socket", MalformedSocket)
    findings_malformed = check.run(gw)
    assert isinstance(findings_malformed, list)
    assert findings_malformed == []

    class MissingResponseTypeSocket(MockSocket):
        def recvfrom(self, bufsize):
            return b"HTTP/1.1 200 OK\r\nSERVER: test\r\n\r\n", (self.target_ip, 1900)

    monkeypatch.setattr("socket.socket", MissingResponseTypeSocket)
    missing_type = check.run(gw)
    assert len(missing_type) == 1
    assert missing_type[0].severity is Severity.INFO
    assert "not tested:" in missing_type[0].description


def test_router_upnp_multicast_uses_lan_interface_and_accepts_gateway_reply(
    monkeypatch,
) -> None:
    from netwatch.checks import RouterUPnPCheck

    reply = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n"
    sent = []

    class FakeSocket:
        def __init__(self, *_args, **_kwargs):
            self.multicast = False

        def settimeout(self, timeout):
            assert 0 < timeout <= 0.5

        def setsockopt(self, level, option, value):
            assert level == socket.IPPROTO_IP
            assert option == socket.IP_MULTICAST_IF
            assert value == socket.inet_aton("192.168.1.10")
            self.multicast = True

        def sendto(self, data, destination):
            sent.append((data, destination))

        def recvfrom(self, _size):
            if not self.multicast:
                raise TimeoutError()
            return reply, ("192.168.1.1", 1900)

        def close(self):
            pass

    monkeypatch.setattr("netwatch.checks.socket.socket", FakeSocket)
    check = RouterUPnPCheck(interface_ip="192.168.1.10")
    findings = check.run(Device(ip="192.168.1.1", is_gateway=True))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert sent[0][1] == ("192.168.1.1", 1900)
    assert sent[1][1] == ("239.255.255.250", 1900)
    assert b"HOST: 239.255.255.250:1900" in sent[1][0]


def test_router_upnp_search_modes_and_igd_description(monkeypatch) -> None:
    from netwatch.checks import RouterUPnPCheck

    target_ip = "192.168.1.1"
    sent = []
    mode = "rootdevice"

    class FakeSocket:
        def __init__(self, *_args):
            self.destination = None
            self.search_target = None

        def settimeout(self, timeout):
            assert 0 < timeout <= 0.5

        def setsockopt(self, level, option, value):
            assert level == socket.IPPROTO_IP
            assert option == socket.IP_MULTICAST_IF
            assert value == socket.inet_aton("192.168.1.10")

        def sendto(self, data, destination):
            self.destination = destination
            match = re.search(rb"\r\nST:\s*(.+)\r\n", data)
            assert match is not None
            self.search_target = match.group(1).decode()
            sent.append((self.search_target, destination, data))
            assert b"MX: 2" in data

        def recvfrom(self, _size):
            should_answer = (
                mode == "rootdevice"
                and self.search_target == "upnp:rootdevice"
                and self.destination == (target_ip, 1900)
            ) or (
                mode == "multicast"
                and self.destination == ("239.255.255.250", 1900)
            )
            if not should_answer:
                raise TimeoutError()
            return (
                (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"ST: {self.search_target}\r\n".encode()
                    + f"LOCATION: http://{target_ip}:1900/root.xml\r\n\r\n".encode()
                ),
                (target_ip, 1900),
            )

        def close(self):
            pass

    class Description:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _limit):
            return (
                b"<deviceType>"
                b"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
                b"</deviceType>"
            )

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == f"http://{target_ip}:1900/root.xml"
            assert timeout == 2.0
            return Description()

    monkeypatch.setattr("netwatch.checks.socket.socket", FakeSocket)
    monkeypatch.setattr(
        "netwatch.checks.urllib.request.build_opener", lambda *_args: Opener()
    )
    check = RouterUPnPCheck(interface_ip="192.168.1.10")
    device = Device(ip=target_ip, is_gateway=True)

    findings, status = check.run_with_result(device)
    assert len(findings) == 1
    assert "InternetGatewayDevice: yes" in status
    assert "InternetGatewayDevice: yes" in findings[0].description
    assert sent[0][0] == "upnp:rootdevice"
    assert sent[0][1] == (target_ip, 1900)

    mode = "multicast"
    sent.clear()
    findings, status = check.run_with_result(device)
    assert len(findings) == 1
    assert "InternetGatewayDevice: yes" in status
    assert sent[0][1] == (target_ip, 1900)
    assert sent[1][1] == ("239.255.255.250", 1900)
    assert b"HOST: 239.255.255.250:1900" in sent[1][2]
    assert b"ST: upnp:rootdevice" in sent[0][2]

    mode = "none"
    sent.clear()
    findings, status = check.run_with_result(device)
    assert findings == []
    assert status == (
        "no SSDP response from 192.168.1.1 (UPnP may still be enabled; "
        "SSDP can be blocked by a firewall)"
    )
    assert [item[0] for item in sent] == [
        "upnp:rootdevice",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "ssdp:all",
        "ssdp:all",
    ]


def test_gateway_detection_and_tagging(monkeypatch) -> None:
    from netwatch.scanner import find_gateway_ip

    # Mock windows route print output
    mock_route_output = (
        "===========================================================================\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.116     55\n"
        "===========================================================================\n"
    )

    class MockCompleted:
        returncode = 0
        stdout = mock_route_output

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockCompleted())
    _mock_module_platform(monkeypatch, "netwatch.scanner", "win32")

    gw = find_gateway_ip(ipaddress.ip_network("192.168.1.0/24"))
    assert gw == "192.168.1.1"

    # When scanning an unrelated subnet, gateway should be None
    assert find_gateway_ip(ipaddress.ip_network("10.0.0.0/24")) is None


def test_router_default_credentials_are_not_sent_over_lan_http(monkeypatch) -> None:
    import urllib.error

    from netwatch.checks import RouterDefaultCredsCheck

    class ChallengeOpener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {"WWW-Authenticate": 'Basic realm="router"'},
                None,
            )

    monkeypatch.setattr(
        "netwatch.checks._router_http_opener", lambda context: ChallengeOpener()
    )
    monkeypatch.setattr(
        "netwatch.checks._try_basic_auth",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("credentials must not be sent")
        ),
    )
    check = RouterDefaultCredsCheck(enabled=True, delay_seconds=0, target_ports=[80])
    findings = check.run(Device(ip="192.168.1.1", is_gateway=True, open_ports=[80]))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "did not send any credentials" in findings[0].description


def test_report_html_includes_score_and_escapes_scan_content() -> None:
    from netwatch.reporting import render_html_report, report_summary

    scan = {
        "id": 7,
        "created_at": "2026-10-08T10:00:00+00:00",
        "cidr": "192.168.1.0/24",
        "discovery_method": "tcp_sweep+arp_cache",
        "devices": [
            {
                "ip": "192.168.1.5",
                "hostname": "<script>alert(1)</script>",
                "open_ports": [80],
                "is_local": True,
            }
        ],
        "findings": [
            {
                "severity": "CRITICAL",
                "title": "<img src=x onerror=alert(1)>",
                "description": "Check details",
                "recommendation": "Fix safely",
            }
        ],
    }
    summary = report_summary(scan, {"new": [], "missing": [], "changed": []})
    assert summary["score"] == 75
    html = render_html_report(scan, summary["baseline_diff"])
    assert "75 / 100" in html
    assert "This machine" in html
    assert "operating system&#x27;s ARP cache" in html
    assert "sleeping or firewalled devices can still be missed" in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "<script>alert(1)</script>" not in html


def test_report_command_generates_html_from_saved_scan(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from netwatch.cli import main

    monkeypatch.setenv("NETWATCH_DB_PATH", str(tmp_path / "report.db"))
    save_scan(
        ScanResult(
            devices=[Device(ip="192.168.1.5", hostname="laptop")],
            cidr="192.168.1.0/24",
        )
    )
    output = tmp_path / "reports" / "latest.html"
    assert main(["report", "--output", str(output)]) == 0
    assert "HTML report written" in capsys.readouterr().out
    assert "laptop" in output.read_text(encoding="utf-8")
