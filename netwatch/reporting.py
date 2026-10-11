from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any

from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ScanResult, is_locally_administered_mac

_SEVERITY_PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def report_summary(
    scan: dict[str, Any], baseline_diff: dict[str, list[str]] | None = None
) -> dict[str, Any]:
    findings = scan.get("findings", [])
    counts = Counter(finding.get("severity", "INFO") for finding in findings)
    penalty = sum(
        _SEVERITY_PENALTIES.get(finding.get("severity", "INFO"), 0)
        for finding in findings
    )
    return {
        "scan_id": scan.get("id"),
        "created_at": scan.get("created_at"),
        "cidr": scan.get("cidr"),
        "score": max(0, 100 - penalty),
        "severity_counts": {
            severity: counts.get(severity, 0) for severity in _SEVERITIES
        },
        "device_count": len(scan.get("devices", [])),
        "finding_count": len(findings),
        "not_tested_count": len(scan.get("not_tested", [])),
        "checks_run": scan.get("checks_run", []),
        "skipped_checks": scan.get("skipped_checks", {}),
        "baseline_diff": baseline_diff,
    }


def render_html_report(
    scan: dict[str, Any],
    baseline_diff: dict[str, list[str]] | None = None,
) -> str:
    summary = report_summary(scan, baseline_diff)
    devices = scan.get("devices", [])
    findings = sorted(
        scan.get("findings", []),
        key=lambda item: -_SEVERITY_PENALTIES.get(item.get("severity", "INFO"), 0),
    )
    severity_rows = "".join(
        f"<tr><th>{severity}</th><td>{summary['severity_counts'][severity]}</td></tr>"
        for severity in _SEVERITIES
    )
    device_rows = (
        "".join(
            "<tr>"
            f"<td>{escape(str(device.get('hostname') or 'Hostname unavailable'))}</td>"
            f"<td>{escape(str(device.get('ip') or ''))}</td>"
            f"<td>{escape(str(device.get('mac') or 'Unavailable'))}</td>"
            f"<td>{'This machine' if device.get('is_local') else 'Gateway' if device.get('is_gateway') else 'Device'}"
            f"{'<br><strong>Private/randomized MAC (likely phone or laptop)</strong>' if is_locally_administered_mac(device.get('mac')) else ''}</td>"
            f"<td>{escape(_trust_label(device.get('trusted')))}</td>"
            f"<td>{escape(', '.join(str(port) for port in device.get('open_ports', [])) or 'None observed')}</td>"
            "</tr>"
            for device in devices
        )
        or '<tr><td colspan="6">No devices were discovered.</td></tr>'
    )
    gateway_fingerprints = [device for device in devices if device.get("is_gateway")]
    if gateway_fingerprints:
        fingerprint_rows = "".join(
            "<tr>"
            f"<th>{escape(str(device.get('ip') or 'Gateway'))}</th>"
            f"<td>{escape(_fingerprint_title(device.get('router_fingerprint', {})))}</td>"
            f"<td>{escape(str(device.get('router_fingerprint', {}).get('server') or 'Unavailable'))}</td>"
            f"<td>{escape(str(device.get('router_fingerprint', {}).get('telnet_banner') or 'Unavailable'))}</td>"
            "</tr>"
            for device in gateway_fingerprints
        )
    else:
        fingerprint_rows = (
            '<tr><td colspan="4">No gateway fingerprint was available.</td></tr>'
        )
    finding_sections = []
    for severity in _SEVERITIES:
        group = [item for item in findings if item.get("severity", "INFO") == severity]
        if not group:
            continue
        cards = "".join(
            "<article class='finding'>"
            f"<h4>{escape(str(finding.get('title', 'Finding')))}</h4>"
            f"<p>{escape(str(finding.get('description', '')))}</p>"
            f"<p><strong>How to fix:</strong> {escape(str(finding.get('recommendation', '')))}</p>"
            "</article>"
            for finding in group
        )
        finding_sections.append(f"<section><h3>{severity}</h3>{cards}</section>")
    finding_cards = (
        "".join(finding_sections)
        or "<p>No implemented checks raised findings during this scan.</p>"
    )
    checks_run = scan.get("checks_run", [])
    skipped_checks = scan.get("skipped_checks", {})
    not_tested = scan.get("not_tested", [])
    checks_run_html = escape(", ".join(checks_run) if checks_run else "None")
    skipped_summary = escape(
        ", ".join(f"{name} ({reason})" for name, reason in skipped_checks.items())
        or "none"
    )
    check_results_html = (
        "".join(
            f"<li>{escape(str(item))}</li>" for item in scan.get("check_results", [])
        )
        or "<li>None</li>"
    )
    skipped_html = (
        "".join(
            f"<li>{escape(str(name))}: {escape(str(reason))}</li>"
            for name, reason in skipped_checks.items()
        )
        if skipped_checks
        else "<li>None</li>"
    )
    not_tested_html = (
        "".join(
            f"<li>Not tested: {escape(str(item.get('name', 'check')))}: "
            f"{escape(str(item.get('reason', '')))}</li>"
            for item in not_tested
        )
        or "<li>None</li>"
    )
    if baseline_diff is None:
        diff_section = "<p>No trusted baseline is available for this comparison.</p>"
    else:
        diff_section = "".join(
            f"<h3>{title}</h3>{_list_html(baseline_diff[key])}"
            for key, title in (
                ("new", "New devices"),
                ("missing", "Missing devices"),
                ("changed", "Changed devices"),
            )
        )
        diff_section += (
            "<p>Devices using private/randomized MAC addresses may reappear as new devices "
            "when their MAC address changes.</p>"
        )

    created_at = escape(str(scan.get("created_at") or "Unknown"))
    cidr = escape(str(scan.get("cidr") or "Unknown"))
    coverage = escape(
        _discovery_coverage(
            str(scan.get("discovery_method") or "tcp_fallback"),
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netwatch scan report</title>
<style>
body {{ color: #1f2937; background: #f3f4f6; font: 16px/1.5 system-ui, sans-serif; margin: 0; }}
main {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
section, .score {{ background: white; border-radius: .6rem; margin: 1rem 0; padding: 1.25rem; }}
h1, h2 {{ margin-top: 0; }} table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border-bottom: 1px solid #d1d5db; padding: .55rem; text-align: left; }}
.score strong {{ font-size: 2.3rem; }} .finding {{ border-left: 5px solid #64748b; margin: 1rem 0; padding: .5rem 1rem; }}
.severity {{ font-weight: 700; }} .finding:has(.severity) {{ border-color: #64748b; }}
.note {{ color: #4b5563; font-size: .95rem; }}
@media print {{ body {{ background: white; }} main {{ margin: 0; max-width: none; }} }}
</style>
</head>
<body><main>
<h1>netwatch scan report</h1>
<p>Scan #{escape(str(summary["scan_id"] or "unsaved"))} · {created_at} · Network: {cidr}</p>
<div class="score"><h2>Security score</h2><strong>{summary["score"]} / 100</strong>
<p>This rough score reflects findings from implemented checks only; it is not a certification.</p></div>
<section><h2>Severity summary</h2><table><tbody>{severity_rows}</tbody></table></section>
<section><h2>Devices</h2><table><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Role</th><th>Baseline</th><th>Open TCP ports</th></tr></thead>
<tbody>{device_rows}</tbody></table></section>
<section><h2>Router fingerprint</h2><table><thead><tr><th>Gateway IP</th><th>HTTP title</th><th>Server header</th><th>Telnet banner</th></tr></thead>
<tbody>{fingerprint_rows}</tbody></table><p>Fingerprinting is read-only and may be incomplete when a service does not respond.</p></section>
<section><h2>Baseline comparison</h2>{diff_section}</section>
<section><h2>Checks run</h2><p>Checks run: {len(checks_run)} | Findings: {len(findings)} | Skipped/opt-in: {skipped_summary}</p>
<p>Check names: {checks_run_html}</p><h3>Results</h3><ul>{check_results_html}</ul>
<h3>Skipped / opt-in</h3><ul>{skipped_html}</ul></section>
<section><h2>Not tested</h2><ul>{not_tested_html}</ul></section>
<section><h2>Findings and recommended fixes</h2>{finding_cards}</section>
<p class="note">{coverage} A score of 100 does not mean the network is secure.</p>
</main></body></html>"""


def _discovery_coverage(discovery_method: str) -> str:
    if discovery_method == "tcp_sweep+arp_cache":
        return (
            "Discovery used TCP checks on the selected ports and the operating system's ARP cache. "
            "Devices absent from the cache that did not answer those selected ports may be missed; "
            "sleeping or firewalled devices can still be missed."
        )
    if discovery_method == "arp":
        return (
            "Discovery used ARP and checked only the selected TCP ports. Devices that do not answer ARP, "
            "including sleeping or firewalled devices, may still be missed."
        )
    return (
        "Discovery used TCP checks on the selected ports only. Devices that do not answer those ports, "
        "including sleeping or firewalled devices, may still be missed."
    )


def discovery_coverage(result: ScanResult) -> str:
    return _discovery_coverage(result.discovery_method)


def print_scan_summary(result: ScanResult, no_color: bool = False) -> None:
    console = Console(no_color=no_color, width=120)
    timestamp = (
        result.timestamp.isoformat(timespec="seconds")
        if result.timestamp
        else "unknown"
    )
    console.print(
        Panel(
            f"[bold]Time (UTC):[/bold] {timestamp}\n"
            f"[bold]Network:[/bold] {result.cidr or 'unknown'}\n"
            f"[bold]Discovery method:[/bold] {result.discovery_method}\n"
            f"[bold]TCP ports checked per address:[/bold] {len(result.scanned_ports)}\n"
            f"[bold]Devices discovered:[/bold] {len(result.devices)}",
            title="Scan summary",
            border_style="blue",
        )
    )
    devices = Table(title="Discovered devices", show_lines=True)
    for column in ("Device", "IP", "Role", "TCP ports", "Baseline"):
        devices.add_column(column)
    if result.devices:
        for device in result.devices:
            trust = (
                "In trusted baseline"
                if device.trusted is True
                else "Not in baseline - review"
                if device.trusted is False
                else "baseline not set"
            )
            devices.add_row(
                escape_markup(device.hostname or "Hostname unavailable"),
                escape_markup(device.ip),
                Text(
                    (
                        "This machine"
                        if device.is_local
                        else "Gateway"
                        if device.is_gateway
                        else "Device"
                    )
                    + (
                        "\nPrivate/randomized MAC (likely phone or laptop)"
                        if is_locally_administered_mac(device.mac)
                        else ""
                    )
                ),
                ", ".join(_describe_port(port) for port in device.open_ports)
                or "none open in selected TCP checks",
                trust,
            )
    else:
        devices.add_row("None discovered", "-", "-", "-", "-")
    console.print(devices)
    for device in result.devices:
        if is_locally_administered_mac(device.mac):
            console.print(
                f"  {escape_markup(device.ip)}: Private/randomized MAC (likely phone or laptop)",
                style="dim",
            )
        for port, banner in sorted(device.banners.items()):
            console.print(f"  Banner on {port}: {escape_markup(banner)}", style="dim")
    gateways = [device for device in result.devices if device.is_gateway]
    if gateways:
        fingerprint_table = Table(title="Router fingerprint")
        fingerprint_table.add_column("Gateway IP")
        fingerprint_table.add_column("HTTP title")
        fingerprint_table.add_column("Server header")
        fingerprint_table.add_column("Telnet banner")
        for gateway in gateways:
            fingerprint = gateway.router_fingerprint
            fingerprint_table.add_row(
                escape_markup(gateway.ip),
                escape_markup(_fingerprint_title(fingerprint)),
                escape_markup(fingerprint.get("server", "Unavailable")),
                escape_markup(fingerprint.get("telnet_banner", "Unavailable")),
            )
        console.print(fingerprint_table)
    if not result.devices:
        console.print(
            "Devices with blocked ARP and closed, filtered, or unscanned ports may still be present.",
            style="yellow",
        )
    if result.findings:
        console.print(f"\nFindings: {len(result.findings)}")
        for finding in result.sorted_findings():
            finding_text = Text()
            finding_text.append(f"{finding.description}\n\n")
            finding_text.append("Suggested action:", style="bold")
            finding_text.append(f"\n{finding.recommendation}")
            console.print(
                Panel(
                    finding_text,
                    title=escape_markup(f"[{finding.severity.value}] {finding.title}"),
                    border_style=_severity_style(finding.severity.value),
                )
            )
    else:
        console.print(
            "\nImplemented checks did not flag any of the open ports observed."
        )
    console.print(
        f"\nCoverage note: {discovery_coverage(result)} "
        "This is not a complete security assessment.",
        style="dim",
    )


def _severity_style(severity: str) -> str:
    return {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "blue",
    }.get(severity, "white")


def _trust_label(trusted: bool | None) -> str:
    if trusted is True:
        return "Trusted"
    if trusted is False:
        return "Not in baseline"
    return "Baseline not set"


def _describe_port(port: int) -> str:
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        1883: "MQTT",
        3389: "Remote Desktop",
        8080: "HTTP alternate",
        8443: "HTTPS alternate",
    }
    service = services.get(port)
    return f"{port} ({service})" if service else str(port)


def _list_html(items: list[str]) -> str:
    if not items:
        return "<p>None</p>"
    return "<ul>" + "".join(f"<li>{escape(str(item))}</li>" for item in items) + "</ul>"


def _fingerprint_title(fingerprint: dict[str, Any]) -> str:
    title = fingerprint.get("http_title")
    if title:
        return str(title)
    reason = fingerprint.get("http_title_error")
    return f"Unavailable ({reason})" if reason else "Unavailable"
