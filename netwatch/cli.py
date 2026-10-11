from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .checks import CHECKS, add_findings
from .config import load_settings
from .models import Device, Finding, NetworkConfig, ScanResult, Severity
from .reporting import (
    discovery_coverage,
    print_scan_summary,
    render_html_report,
    report_summary,
)
from .scanner import NetworkScopeError, collect_router_fingerprint, discover_devices
from .storage import (
    annotate_baseline_status,
    diff_against_baseline,
    get_scan,
    list_known_devices,
    list_scans,
    save_baseline,
    save_scan,
)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cidr", default="192.168.1.0/24", help="Subnet to scan")
    common.add_argument("--interface", help="Network interface to use")
    common.add_argument(
        "--ports", default="top100", help="Port set or comma-separated list"
    )
    common.add_argument("--only", help="Only run named checks")
    common.add_argument("--skip", help="Skip named checks")
    common.add_argument(
        "--timeout", type=float, default=0.5, help="Per-connection timeout"
    )
    common.add_argument(
        "--concurrency", type=int, default=200, help="Parallel connections"
    )
    common.add_argument("--json", action="store_true", help="Machine-readable output")
    common.add_argument("--no-color", action="store_true", help="Disable colors")
    common.add_argument(
        "--allow-public", action="store_true", help="Allow public IP ranges"
    )
    common.add_argument(
        "--yes",
        action="store_true",
        help="Confirm you own or have permission to scan the target",
    )
    common.add_argument(
        "--trust-all",
        action="store_true",
        help="Trust every device found by baseline (requires --yes for non-interactive use)",
    )
    common.add_argument(
        "--check-creds",
        action="store_true",
        help="Opt-in to test factory default credentials against your gateway",
    )
    common.add_argument(
        "--expected-dns",
        help="Comma-separated list of expected DNS resolver IPs",
    )
    common.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase output verbosity"
    )

    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Home network security scanner and change monitor.",
        parents=[common],
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "scan", help="Discover hosts, scan ports, and run checks", parents=[common]
    )
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Review and trust devices in the current scan",
        parents=[common],
    )
    baseline_parser.add_argument(
        "--force",
        action="store_true",
        help="Allow a partial baseline; devices without MAC addresses are never saved",
    )
    subparsers.add_parser(
        "diff", help="Show changed devices versus the baseline", parents=[common]
    )
    subparsers.add_parser(
        "devices", help="List known devices and trust state", parents=[common]
    )
    report_parser = subparsers.add_parser(
        "report", help="Generate a report from a saved scan", parents=[common]
    )
    report_parser.add_argument(
        "--scan-id", type=int, help="Saved scan ID (defaults to the latest scan)"
    )
    report_parser.add_argument(
        "--output", default="netwatch-report.html", help="HTML report path"
    )
    subparsers.add_parser(
        "history", help="View the history of local scans", parents=[common]
    )
    subparsers.add_parser("checks", help="List available checks", parents=[common])

    return parser


def _print_scan_summary(result, no_color: bool = False) -> None:
    print_scan_summary(result, no_color=no_color)


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON")


def _scan_exit_code(findings: Sequence[Finding], fail_on: str | None) -> int:
    if any(finding.name == "new_device" for finding in findings):
        return 2
    threshold = Severity[fail_on.upper()].rank if fail_on else Severity.HIGH.rank
    if any(finding.severity.rank >= threshold for finding in findings):
        return 1
    return 0


def _print_devices(rows: list[dict]) -> None:
    if not rows:
        print("No known devices in the baseline.")
        return
    print("Known devices:")
    for row in rows:
        state = "trusted" if row["trusted"] else "not in trusted baseline"
        mac = "MAC unavailable" if row["mac"] == row["ip"] else row["mac"]
        print(f"- {row['hostname'] or row['ip']} | {row['ip']} | {mac} | {state}")


def _print_diff(diff: dict[str, list[str]]) -> None:
    print("Network diff against trusted baseline:")
    print(f"New devices: {', '.join(diff['new']) if diff['new'] else 'none'}")
    print(
        f"Missing devices: {', '.join(diff['missing']) if diff['missing'] else 'none'}"
    )
    print(
        f"Changed devices: {', '.join(diff['changed']) if diff['changed'] else 'none'}"
    )
    print(
        "Note: this comparison only sees devices responding on the selected TCP ports; "
        "a device may appear missing simply because it did not respond during this scan. "
        "Devices using private/randomized MAC addresses may reappear as new devices when their MAC changes."
    )


def _confirm_baseline_devices(
    result, trust_all: bool, display_devices: bool = True
) -> bool:
    if not result.devices:
        print(
            "No devices were discovered. No baseline was saved; devices may not have responded to ARP "
            "or to the selected TCP ports.",
            file=sys.stderr,
        )
        return False
    if display_devices:
        print("\nDevices to include in the trusted baseline:")
        if result.discovery_method == "tcp_fallback":
            print(
                "  WARNING: ARP discovery was unavailable. TCP fallback can miss devices "
                "that do not have a selected port open."
            )
        for device in result.devices:
            gw_tag = " (Gateway)" if device.is_gateway else ""
            print(
                f"  - {device.hostname or 'hostname unavailable'} | {device.ip}{gw_tag} | {device.mac or 'MAC unavailable'}"
            )
    if trust_all:
        return True
    try:
        answer = (
            input(
                "\nOnly continue if you recognize every listed device. Trust all of them? [y/N] "
            )
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in {"y", "yes"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return interactive_menu(parser)

    return _dispatch(args, parser)


def interactive_menu(parser: argparse.ArgumentParser) -> int:
    print("netwatch - Home Network Security Monitor")
    print("Choose an action:")
    while True:
        print("\n  1) Scan network")
        print("  2) Save trusted baseline")
        print("  3) Compare with baseline")
        print("  4) List known devices")
        print("  5) Scan history")
        print("  6) Available checks")
        print("  7) Generate HTML report")
        print("  8) Help")
        print("  0) Exit")
        try:
            choice = input("\nnetwatch> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in {"0", "exit", "quit", "q"}:
            print("Goodbye.")
            return 0
        if choice in {
            "1",
            "scan",
            "2",
            "baseline",
            "3",
            "diff",
            "4",
            "devices",
            "5",
            "history",
            "6",
            "checks",
            "7",
            "report",
        }:
            command = {
                "1": "scan",
                "scan": "scan",
                "2": "baseline",
                "baseline": "baseline",
                "3": "diff",
                "diff": "diff",
                "4": "devices",
                "devices": "devices",
                "5": "history",
                "history": "history",
                "6": "checks",
                "checks": "checks",
                "7": "report",
                "report": "report",
            }[choice]
            if command in {"devices", "history", "checks", "report"}:
                _dispatch(parser.parse_args([command]), parser)
                continue
            try:
                cidr = input("LAN CIDR to scan [192.168.1.0/24]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            arguments = [command]
            if cidr:
                arguments.extend(["--cidr", cidr])
            try:
                _dispatch(parser.parse_args(arguments), parser)
            except SystemExit:
                continue
            continue
        if choice in {"8", "help"}:
            parser.print_help()
            continue
        print("Choose 1, 2, 3, 4, 5, 6, 7, 8, or 0.")


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = NetworkConfig.from_args(args)
    settings = load_settings(config)
    settings.check_creds = bool(args.check_creds)
    if args.command in {"scan", "diff"} and settings.fail_on is not None:
        fail_on = settings.fail_on.strip().upper()
        if fail_on not in Severity.__members__:
            print(
                f"Invalid report.fail_on value {settings.fail_on!r}. "
                f"Choose one of: {', '.join(Severity.__members__)}.",
                file=sys.stderr,
            )
            return 3
        settings.fail_on = fail_on
    check_names = {check.name for check in CHECKS}
    requested_checks = set(settings.only or ()) | set(settings.skip or ())
    unknown_checks = requested_checks - check_names
    if unknown_checks:
        print(
            f"Unknown check name(s): {', '.join(sorted(unknown_checks))}. Use 'netwatch checks' to list checks.",
            file=sys.stderr,
        )
        return 3

    if args.command == "scan":
        if not _confirm_scan_scope(args.yes):
            print(
                "Scan cancelled; confirm that you own or have permission to scan the target.",
                file=sys.stderr,
            )
            return 3
        try:
            result = discover_devices(settings)
        except NetworkScopeError as exc:
            print(f"Scan refused: {exc}", file=sys.stderr)
            return 3
        collect_router_fingerprint(result)
        has_baseline = annotate_baseline_status(result)
        add_findings(
            result,
            settings.only,
            settings.skip,
            check_creds=settings.check_creds,
            expected_dns=settings.expected_dns,
            ignore=settings.ignore_findings,
        )
        save_scan(result)
        if settings.json:
            payload = {
                "scan": {
                    "timestamp": result.timestamp,
                    "cidr": result.cidr,
                    "discovery_method": result.discovery_method,
                    "gateway_ip": result.gateway_ip,
                    "scanned_ports": result.scanned_ports,
                    "baseline_exists": has_baseline,
                    "coverage": f"{discovery_coverage(result)} Not a complete security assessment.",
                    "checks_run": result.checks_run,
                    "finding_count": len(result.findings),
                    "skipped_checks": result.skipped_checks,
                    "check_results": result.check_results,
                },
                "devices": [asdict(device) for device in result.devices],
                "findings": [asdict(finding) for finding in result.findings],
                "not_tested": [asdict(item) for item in result.not_tested],
            }
            print(json.dumps(payload, indent=2, default=_json_default))
        else:
            _print_scan_summary(result, no_color=settings.no_color)
            _print_check_execution_summary(result)
        return _scan_exit_code(result.findings, settings.fail_on)

    if args.command == "baseline":
        if not _confirm_scan_scope(args.yes):
            print(
                "Baseline cancelled; confirm that you own or have permission to scan the target.",
                file=sys.stderr,
            )
            return 3
        if settings.json and not args.trust_all:
            print(
                "JSON baseline mode requires --trust-all so the trust decision is explicit.",
                file=sys.stderr,
            )
            return 3
        try:
            result = discover_devices(settings)
        except NetworkScopeError as exc:
            print(f"Scan refused: {exc}", file=sys.stderr)
            return 3
        collect_router_fingerprint(result)
        force = getattr(args, "force", False)
        missing_macs = [
            device for device in result.devices if not device.mac and not device.is_local
        ]
        incomplete = result.discovery_method == "tcp_fallback" or bool(missing_macs)
        if incomplete and not force:
            reasons = []
            if result.discovery_method == "tcp_fallback":
                reasons.append(
                    "discovery used TCP fallback and may have missed devices"
                )
            if missing_macs:
                reasons.append(
                    f"{len(missing_macs)} discovered device(s) lack a MAC address"
                )
            print(
                "Baseline refused: "
                + "; ".join(reasons)
                + ". Partial data can create a misleading trusted baseline. "
                "Review the results and rerun with --force only if you accept that limitation.",
                file=sys.stderr,
            )
            return 3
        if force and incomplete:
            result.devices = [device for device in result.devices if device.mac]
            if not result.devices:
                print(
                    "Baseline refused: no discovered devices have a MAC address. "
                    "--force never creates IP-based device identities.",
                    file=sys.stderr,
                )
                return 3
            print(
                f"WARNING: forcing a partial baseline. {len(missing_macs)} device(s) without MAC addresses "
                "will not be saved, and TCP fallback may have missed other devices.",
                file=sys.stderr,
            )
        annotate_baseline_status(result)
        add_findings(
            result,
            settings.only,
            settings.skip,
            check_creds=settings.check_creds,
            expected_dns=settings.expected_dns,
            ignore=settings.ignore_findings,
        )
        if not _confirm_baseline_devices(
            result,
            args.trust_all,
            display_devices=not settings.json,
        ):
            print("Baseline cancelled; no devices were trusted.", file=sys.stderr)
            return 3
        saved = save_baseline(result)
        if settings.json:
            print(
                json.dumps(
                    {
                        "saved": [device.mac for device in saved],
                        "skipped_without_mac": len(missing_macs) if force else 0,
                        "partial_data_override": bool(force and incomplete),
                        "checks_run": result.checks_run,
                        "finding_count": len(result.findings),
                        "skipped_checks": result.skipped_checks,
                        "check_results": result.check_results,
                        "not_tested": [asdict(item) for item in result.not_tested],
                    },
                    indent=2,
                )
            )
        else:
            _print_check_execution_summary(result, include_results=False)
            print(f"Trusted baseline saved for {len(saved)} devices by MAC address.")
        return 0

    if args.command == "devices":
        rows = list_known_devices()
        if settings.json:
            print(json.dumps(rows, indent=2))
        else:
            _print_devices(rows)
        return 0

    if args.command == "diff":
        if not _confirm_scan_scope(args.yes):
            print(
                "Diff cancelled; confirm that you own or have permission to scan the target.",
                file=sys.stderr,
            )
            return 3
        try:
            result = discover_devices(settings)
        except NetworkScopeError as exc:
            print(f"Scan refused: {exc}", file=sys.stderr)
            return 3
        collect_router_fingerprint(result)
        has_baseline = annotate_baseline_status(result)
        add_findings(
            result,
            settings.only,
            settings.skip,
            check_creds=settings.check_creds,
            expected_dns=settings.expected_dns,
            ignore=settings.ignore_findings,
        )
        if not has_baseline:
            save_scan(result)
            if settings.json:
                print(
                    json.dumps(
                        {
                            "baseline_exists": False,
                            "message": "Save a trusted baseline first.",
                            "checks_run": result.checks_run,
                            "finding_count": len(result.findings),
                            "skipped_checks": result.skipped_checks,
                            "check_results": result.check_results,
                            "not_tested": [asdict(item) for item in result.not_tested],
                        },
                        indent=2,
                    )
                )
            else:
                _print_check_execution_summary(result, include_results=False)
                print(
                    "No trusted baseline exists yet. Review the scan, then save one with 'netwatch baseline'."
                )
            return _scan_exit_code(result.findings, settings.fail_on)
        diff = diff_against_baseline(result)
        save_scan(result)
        if settings.json:
            print(
                json.dumps(
                    {
                        "baseline_exists": True,
                        **diff,
                        "checks_run": result.checks_run,
                        "finding_count": len(result.findings),
                        "skipped_checks": result.skipped_checks,
                        "check_results": result.check_results,
                        "not_tested": [asdict(item) for item in result.not_tested],
                    },
                    indent=2,
                )
            )
        else:
            _print_check_execution_summary(result, include_results=False)
            _print_diff(diff)
            for finding in result.sorted_findings():
                print(f"\n[{finding.severity.value}] {finding.title}")
                print(f"What this means: {finding.description}")
                print(f"Suggested action: {finding.recommendation}")
        if diff["new"]:
            return 2
        return _scan_exit_code(result.findings, settings.fail_on)

    if args.command == "history":
        history = list_scans()
        if settings.json:
            print(json.dumps(history, indent=2))
        elif not history:
            print("No scans have been saved yet.")
        else:
            print("Recent scans:")
            for history_entry in history:
                print(
                    f"  #{history_entry['id']} | {history_entry['created_at']} | "
                    f"{history_entry['cidr'] or 'unknown network'} | "
                    f"{history_entry['device_count']} devices | {history_entry['finding_count']} findings | "
                    f"{history_entry['discovery_method'] or 'unknown method'}"
                )
        return 0

    if args.command == "checks":
        checks = [
            {"name": check.name, "description": check.description} for check in CHECKS
        ]
        if settings.json:
            print(json.dumps(checks, indent=2))
        else:
            print("Implemented checks:")
            for check in checks:
                print(f"  {check['name']}: {check['description']}")
        return 0

    if args.command == "report":
        scan = get_scan(args.scan_id)
        if scan is None:
            message = (
                f"No saved scan found with ID {args.scan_id}."
                if args.scan_id is not None
                else "No saved scans are available. Run 'netwatch scan' first."
            )
            print(message, file=sys.stderr)
            return 3
        saved_devices = [
            Device(
                ip=device["ip"],
                mac=device.get("mac"),
                hostname=device.get("hostname"),
                vendor=device.get("vendor"),
                trusted=device.get("trusted"),
                is_gateway=device.get("is_gateway", False),
            )
            for device in scan.get("devices", [])
        ]
        baseline_diff = (
            diff_against_baseline(ScanResult(devices=saved_devices))
            if any(row["trusted"] for row in list_known_devices())
            else None
        )
        summary = report_summary(scan, baseline_diff)
        if settings.json:
            print(
                json.dumps(
                    {"summary": summary, "scan": scan}, indent=2, default=_json_default
                )
            )
            return 0
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                render_html_report(scan, baseline_diff),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"Could not write report to {output_path}: {exc}", file=sys.stderr)
            return 3
        print(f"HTML report written to {output_path.resolve()}")
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


def _confirm_scan_scope(yes: bool) -> bool:
    if yes:
        return True
    print("Only scan a network you own or have explicit permission to test.")
    try:
        answer = (
            input("Do you own or have permission to scan this network? [y/N] ")
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in {"y", "yes"}


def _print_check_execution_summary(
    result: ScanResult, include_results: bool = True
) -> None:
    skipped = (
        ", ".join(
            f"{name} ({reason})" for name, reason in result.skipped_checks.items()
        )
        or "none"
    )
    print(
        f"Checks run: {len(result.checks_run)} | Findings: {len(result.findings)} | "
        f"Skipped/opt-in: {skipped}"
    )
    if include_results and result.check_results:
        print("Check results:")
        for status in result.check_results:
            print(f"  {status}")
    print("Not tested:")
    if result.not_tested:
        for item in result.not_tested:
            target = f" on {item.target}" if item.target else ""
            print(f"  - {item.name}{target}: {item.reason}")
    else:
        print("  None")


if __name__ == "__main__":
    raise SystemExit(main())
