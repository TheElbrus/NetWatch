from __future__ import annotations

import tomllib
import warnings
from pathlib import Path

from .models import NetworkConfig


def _coerce_list(value: object | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _normalize_ignore_rules(raw: object | None) -> list[dict[str, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]

    rules: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        check_name = str(item.get("check") or item.get("name") or "").strip()
        target = str(
            item.get("target") or item.get("ip") or item.get("device") or ""
        ).strip()
        if not check_name:
            continue
        rules.append({"check": check_name, "target": target})
    return rules


def load_settings(config: NetworkConfig | None = None) -> NetworkConfig:
    """Return the effective network configuration for the current run."""
    base = config or NetworkConfig()
    app_dir = Path.home() / ".netwatch"
    app_dir.mkdir(exist_ok=True)

    config_paths = [
        app_dir / "config.toml",
        Path.home() / ".config" / "netwatch" / "config.toml",
    ]
    for cfg_path in config_paths:
        if cfg_path.is_file():
            try:
                with cfg_path.open("rb") as f:
                    data = tomllib.load(f)
                scan_sec = data.get("scan", {})
                network_sec = data.get("network", {})
                checks_sec = data.get("checks", {})
                report_sec = data.get("report", {})
                ignore_sec = data.get("ignore", {})

                if base.cidr == "192.168.1.0/24" and "cidr" in network_sec:
                    base.cidr = str(network_sec["cidr"])
                if base.interface is None and "interface" in scan_sec:
                    base.interface = str(scan_sec["interface"])
                if base.interface is None and "interface" in network_sec:
                    base.interface = str(network_sec["interface"])
                if base.ports == "top100" and "ports" in scan_sec:
                    base.ports = str(scan_sec["ports"])
                if base.timeout == 0.5 and "timeout" in scan_sec:
                    base.timeout = float(scan_sec["timeout"])
                if base.concurrency == 200 and "concurrency" in scan_sec:
                    base.concurrency = int(scan_sec["concurrency"])
                if not base.allow_public and "allow_public" in network_sec:
                    base.allow_public = bool(network_sec["allow_public"])
                if not base.check_creds and "check_creds" in checks_sec:
                    base.check_creds = bool(checks_sec["check_creds"])
                if base.only is None and "only" in checks_sec:
                    base.only = _coerce_list(checks_sec["only"])
                if base.skip is None and "skip" in checks_sec:
                    base.skip = _coerce_list(checks_sec["skip"])
                if not base.expected_dns and "expected_dns" in network_sec:
                    base.expected_dns = _coerce_list(network_sec["expected_dns"])
                if not base.ignore_findings and "findings" in ignore_sec:
                    base.ignore_findings = _normalize_ignore_rules(
                        ignore_sec["findings"]
                    )
                if base.fail_on is None and "fail_on" in report_sec:
                    base.fail_on = str(report_sec["fail_on"])
                break
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                warnings.warn(
                    f"Could not load netwatch configuration from {cfg_path}: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return base
