from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from .models import Device, Finding, NotTested, ScanResult

_MAC_ADDRESS = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def _normalized_mac(mac: str | None) -> str | None:
    if not mac or not _MAC_ADDRESS.fullmatch(mac):
        return None
    return mac.lower().replace("-", ":")


def get_db_path() -> Path:
    override = os.environ.get("NETWATCH_DB_PATH")
    if override:
        return Path(override)
    return Path.home() / ".netwatch" / "netwatch.db"


def _connect() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS known_devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            trusted INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            raw_json TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            payload TEXT NOT NULL
        )
        """
    )
    return connection


def _device_payload(device: Device) -> dict[str, Any]:
    return {
        "ip": device.ip,
        "mac": device.mac,
        "vendor": device.vendor,
        "hostname": device.hostname,
        "trusted": device.trusted,
        "is_gateway": device.is_gateway,
        "is_local": device.is_local,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "open_ports": device.open_ports,
        "banners": device.banners,
        "router_fingerprint": device.router_fingerprint,
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "name": finding.name,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
    }


def _not_tested_payload(item: NotTested) -> dict[str, Any]:
    return {"name": item.name, "reason": item.reason, "target": item.target}


def _upsert_device(
    connection: sqlite3.Connection,
    device: Device,
    trusted: bool | None = None,
) -> None:
    identity = device.mac or device.ip
    existing = connection.execute(
        "SELECT trusted, first_seen FROM known_devices WHERE mac = ?",
        (identity,),
    ).fetchone()
    trusted = (
        trusted
        if trusted is not None
        else bool(existing["trusted"])
        if existing
        else False
    )
    first_seen = (
        existing["first_seen"]
        if existing and existing["first_seen"]
        else device.last_seen.isoformat()
        if device.last_seen
        else None
    )
    connection.execute(
        """
        INSERT INTO known_devices (mac, ip, hostname, vendor, trusted, first_seen, last_seen, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            ip = excluded.ip,
            hostname = excluded.hostname,
            vendor = excluded.vendor,
            trusted = excluded.trusted,
            last_seen = excluded.last_seen,
            raw_json = excluded.raw_json
        """,
        (
            identity,
            device.ip,
            device.hostname,
            device.vendor,
            1 if trusted else 0,
            first_seen,
            device.last_seen.isoformat() if device.last_seen else None,
            json.dumps(_device_payload(device)),
        ),
    )


def save_scan(result: ScanResult) -> int:
    created_at = result.timestamp.isoformat() if result.timestamp else "unknown"
    payload = {
        "cidr": result.cidr,
        "discovery_method": result.discovery_method,
        "gateway_ip": result.gateway_ip,
        "scanned_ports": result.scanned_ports,
        "checks_run": result.checks_run,
        "skipped_checks": result.skipped_checks,
        "check_results": result.check_results,
        "devices": [_device_payload(device) for device in result.devices],
        "findings": [_finding_payload(finding) for finding in result.findings],
        "not_tested": [_not_tested_payload(item) for item in result.not_tested],
    }
    with _connect() as connection:
        for device in result.devices:
            _upsert_device(connection, device)
        cursor = connection.execute(
            "INSERT INTO scans (created_at, payload) VALUES (?, ?)",
            (created_at, json.dumps(payload)),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("SQLite did not return an ID for the saved scan.")
        return cursor.lastrowid


def save_baseline(result: ScanResult) -> list[Device]:
    mac_devices = [device for device in result.devices if _normalized_mac(device.mac)]
    if not mac_devices:
        return []
    with _connect() as connection:
        for device in mac_devices:
            device.trusted = True
            _upsert_device(connection, device, trusted=True)

        payload = {
            "cidr": result.cidr,
            "discovery_method": result.discovery_method,
            "gateway_ip": result.gateway_ip,
            "scanned_ports": result.scanned_ports,
            "checks_run": result.checks_run,
            "skipped_checks": result.skipped_checks,
            "check_results": result.check_results,
            "devices": [_device_payload(device) for device in mac_devices],
            "findings": [_finding_payload(finding) for finding in result.findings],
            "not_tested": [_not_tested_payload(item) for item in result.not_tested],
        }
        created_at = result.timestamp.isoformat() if result.timestamp else "unknown"
        connection.execute(
            "INSERT INTO scans (created_at, payload) VALUES (?, ?)",
            (created_at, json.dumps(payload)),
        )
    return mac_devices


def list_known_devices() -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT mac, ip, hostname, vendor, trusted, first_seen, last_seen
            FROM known_devices
            ORDER BY hostname, ip
            """
        ).fetchall()
    return [dict(row) for row in rows]


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("History limit must be at least 1.")
    with _connect() as connection:
        rows = connection.execute(
            "SELECT id, created_at, payload FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    history = []
    for row in rows:
        payload = json.loads(row["payload"])
        history.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "cidr": payload.get("cidr"),
                "discovery_method": payload.get("discovery_method"),
                "device_count": len(payload.get("devices", [])),
                "finding_count": len(payload.get("findings", [])),
            }
        )
    return history


def get_scan(scan_id: int | None = None) -> dict[str, Any] | None:
    """Return one saved scan, defaulting to the most recent scan."""
    with _connect() as connection:
        if scan_id is None:
            row = connection.execute(
                "SELECT id, created_at, payload FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT id, created_at, payload FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
    if row is None:
        return None
    payload = json.loads(row["payload"])
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        **payload,
    }


def annotate_baseline_status(result: ScanResult) -> bool:
    """Set trust to true/false when a trusted baseline exists; otherwise unknown."""
    rows = [row for row in list_known_devices() if row["trusted"]]
    rows = [row for row in rows if _normalized_mac(row["mac"])]
    if not rows:
        for device in result.devices:
            device.trusted = None
        return False

    baseline_macs = {_normalized_mac(row["mac"]) for row in rows}
    for device in result.devices:
        device_mac = _normalized_mac(device.mac)
        device.trusted = device_mac in baseline_macs if device_mac else None
    return True


def diff_against_baseline(result: ScanResult) -> dict[str, list[str]]:
    baseline_rows = [row for row in list_known_devices() if row["trusted"]]
    baseline_rows = [row for row in baseline_rows if _normalized_mac(row["mac"])]
    current_by_identity = {
        normalized_mac: device
        for device in result.devices
        if (normalized_mac := _normalized_mac(device.mac)) is not None
    }
    baseline_by_identity = {_normalized_mac(row["mac"]): row for row in baseline_rows}
    matched_baseline: set[str] = set()
    new_devices: list[str] = []
    changed_devices: list[str] = []

    for identity, device in current_by_identity.items():
        baseline = baseline_by_identity.get(identity)
        if baseline is None:
            new_devices.append(device.mac or identity)
            continue
        matched_baseline.add(_normalized_mac(baseline["mac"]) or "")
        if (
            baseline["ip"] != device.ip
            or baseline["hostname"] != device.hostname
            or baseline["vendor"] != device.vendor
        ):
            changed_devices.append(device.mac or identity)

    missing_devices = sorted(
        row["mac"]
        for row in baseline_rows
        if _normalized_mac(row["mac"]) not in matched_baseline
    )
    return {
        "new": sorted(new_devices),
        "missing": missing_devices,
        "changed": sorted(changed_devices),
    }
