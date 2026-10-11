from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return order[self.value]


def is_locally_administered_mac(mac: str | None) -> bool:
    if not mac:
        return False
    octets = mac.replace("-", ":").split(":")
    if len(octets) != 6:
        return False
    try:
        first_octet = int(octets[0], 16)
    except ValueError:
        return False
    return first_octet & 0b10 != 0


@dataclass(slots=True)
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    trusted: bool | None = None
    is_gateway: bool = False
    is_local: bool = False
    last_seen: datetime | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    router_fingerprint: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    name: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)
    target: str | None = None

    @property
    def rank(self) -> int:
        return self.severity.rank


@dataclass(slots=True)
class NotTested:
    name: str
    reason: str
    target: str | None = None


@dataclass(slots=True)
class ScanResult:
    devices: list[Device] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    not_tested: list[NotTested] = field(default_factory=list)
    timestamp: datetime | None = None
    cidr: str | None = None
    scanned_ports: list[int] = field(default_factory=list)
    discovery_method: str = "tcp"
    gateway_ip: str | None = None
    checks_run: list[str] = field(default_factory=list)
    skipped_checks: dict[str, str] = field(default_factory=dict)
    check_results: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_device(self, device: Device) -> None:
        self.devices.append(device)

    def sorted_findings(self, reverse: bool = True) -> list[Finding]:
        return sorted(self.findings, key=lambda item: item.rank, reverse=reverse)


@dataclass(slots=True)
class NetworkConfig:
    cidr: str = "192.168.1.0/24"
    interface: str | None = None
    ports: str = "top100"
    timeout: float = 0.5
    concurrency: int = 200
    only: list[str] | None = None
    skip: list[str] | None = None
    allow_public: bool = False
    json: bool = False
    no_color: bool = False
    verbose: int = 0
    check_creds: bool = False
    expected_dns: list[str] | None = None
    ignore_findings: list[dict[str, str]] = field(default_factory=list)
    fail_on: str | None = None

    @classmethod
    def from_args(cls, args: object) -> NetworkConfig:
        opt = getattr(args, "only", None)
        skip = getattr(args, "skip", None)
        expected = getattr(args, "expected_dns", None)
        if isinstance(expected, str) and expected:
            parsed_expected = [
                item.strip() for item in expected.split(",") if item.strip()
            ]
        elif isinstance(expected, list):
            parsed_expected = expected
        else:
            parsed_expected = None
        return cls(
            cidr=getattr(args, "cidr", "192.168.1.0/24"),
            interface=getattr(args, "interface", None),
            ports=getattr(args, "ports", "top100"),
            timeout=float(getattr(args, "timeout", 0.5)),
            concurrency=int(getattr(args, "concurrency", 200)),
            only=(
                [name.strip() for name in opt.split(",") if name.strip()]
                if isinstance(opt, str) and opt
                else None
            ),
            skip=(
                [name.strip() for name in skip.split(",") if name.strip()]
                if isinstance(skip, str) and skip
                else None
            ),
            allow_public=bool(getattr(args, "allow_public", False)),
            json=bool(getattr(args, "json", False)),
            no_color=bool(getattr(args, "no_color", False)),
            verbose=getattr(args, "verbose", 0),
            check_creds=bool(getattr(args, "check_creds", False)),
            expected_dns=parsed_expected,
        )
