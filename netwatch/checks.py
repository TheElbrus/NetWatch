from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import psutil

from .models import Device, Finding, NotTested, ScanResult, Severity


class Check(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    def run(self, device: Device) -> list[Finding]:
        """Inspect one discovered device and return zero or more findings."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _router_http_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )


_ROUTER_BRANDS = (
    ("tp-link", "TP-Link"),
    ("netgear", "NETGEAR"),
    ("asus", "ASUS"),
    ("huawei", "Huawei"),
    ("zte", "ZTE"),
    ("mikrotik", "MikroTik"),
    ("ubiquiti", "Ubiquiti"),
    ("openwrt", "OpenWrt"),
)


@dataclass(frozen=True, slots=True)
class ReachableServiceCheck:
    name: str
    port: int
    title: str
    severity: Severity
    description: str
    recommendation: str
    requires_http_banner: bool = False

    def run(self, device: Device) -> list[Finding]:
        if device.is_local or self.port not in device.open_ports:
            return []
        banner = device.banners.get(self.port, "")
        if self.requires_http_banner and not banner.upper().startswith("HTTP/"):
            return []
        severity = self.severity
        recommendation = self.recommendation
        if self.name == "smb_exposed":
            try:
                if ipaddress.ip_address(device.ip).is_private:
                    severity = Severity.LOW
            except ValueError:
                pass
        if self.name == "telnet_open" and device.is_gateway:
            generic_fix = (
                "Telnet sends login credentials and sessions in plaintext. Disable it and use a secure "
                "administration method. ISP-managed routers may not allow disabling it; check the admin panel, "
                "change the admin password, and contact your ISP for help."
            )
            fingerprint = " ".join(device.router_fingerprint.values()).casefold()
            brand = next(
                (
                    display
                    for marker, display in _ROUTER_BRANDS
                    if marker in fingerprint
                ),
                None,
            )
            recommendation = (
                f"The router fingerprint suggests {brand}; consult documentation for the exact model's Telnet "
                f"controls. {generic_fix}"
                if brand
                else generic_fix
            )
        return [
            Finding(
                name=self.name,
                title=f"{self.title} on {device.ip}",
                description=(
                    f"A TCP connection to port {self.port} succeeded from the machine running netwatch. "
                    "This confirms reachability only; it does not prove the service is vulnerable."
                ),
                severity=severity,
                recommendation=recommendation,
                evidence=[f"TCP port {self.port} accepted a connection"],
            )
        ]


class NewDeviceCheck:
    name = "new_device"
    description = "Reports devices not present in the saved trusted baseline."

    def run(self, device: Device) -> list[Finding]:
        if device.trusted is not False:
            return []
        identity = device.mac or device.ip
        return [
            Finding(
                name=self.name,
                title=f"Device not in trusted baseline: {device.ip}",
                description=(
                    f"{device.hostname or 'A device'} ({identity}) responded on the network but is not in "
                    "the trusted baseline. This does not establish that it is malicious."
                ),
                severity=Severity.HIGH,
                recommendation=(
                    "Check the device name, IP, and MAC address against your router's connected-device list. "
                    "If you recognize it, review and explicitly add it to your trusted baseline."
                ),
                evidence=[f"Device identity {identity} is not in the trusted baseline"],
            )
        ]


def _not_tested_finding(name: str, reason: str, target: str | None = None) -> Finding:
    return Finding(
        name=name,
        title=f"Not tested: {name}",
        description=f"not tested: {reason}.",
        severity=Severity.INFO,
        recommendation="Review this limitation if the check is important to your assessment.",
        evidence=[f"not tested: {reason}"],
        target=target,
    )


class RouterUPnPCheck:
    name = "router_upnp"
    description = (
        "Checks whether a private-network device responds to UPnP/SSDP discovery."
    )

    def __init__(self, timeout: float = 3.0, interface_ip: str | None = None) -> None:
        self.timeout = timeout
        self.interface_ip = interface_ip

    def run(self, device: Device) -> list[Finding]:
        findings, _status = self.run_with_result(device)
        return findings

    def run_with_result(self, device: Device) -> tuple[list[Finding], str]:
        if device.is_local:
            return [], f"not tested on this machine ({device.ip})"
        try:
            address = ipaddress.ip_address(device.ip)
        except ValueError:
            return [], f"not tested: invalid IP address ({device.ip})"
        if not (address.is_private or address.is_loopback):
            return [], f"not tested: non-private target ({device.ip})"

        data: bytes | None = None
        deadline = time.monotonic() + self.timeout
        search_targets = (
            "upnp:rootdevice",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "ssdp:all",
        )
        answered_st: str | None = None
        for search_target in search_targets:
            for destination, host in (
                ((device.ip, 1900), device.ip),
                (("239.255.255.250", 1900), "239.255.255.250"),
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                message = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    f"HOST: {host}:1900\r\n"
                    'MAN: "ssdp:discover"\r\n'
                    f"MX: 2\r\nST: {search_target}\r\n\r\n"
                ).encode("ascii")
                sock: socket.socket | None = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(min(remaining, self.timeout / 6))
                    if destination[0] == "239.255.255.250" and self.interface_ip:
                        sock.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_MULTICAST_IF,
                            socket.inet_aton(self.interface_ip),
                        )
                    sock.sendto(message, destination)
                    response, source = sock.recvfrom(4096)
                    if response and source[0] == device.ip:
                        response_text = response.decode("utf-8", errors="replace")
                        if re.match(
                            r"^HTTP/1\.[01]\s+200(?:\s|$)", response_text.strip()
                        ):
                            data = response
                            answered_st = search_target
                            break
                except (TimeoutError, OSError):
                    pass
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
            if data or time.monotonic() >= deadline:
                break

        if not data:
            return [], (
                f"no SSDP response from {device.ip} (UPnP may still be enabled; "
                "SSDP can be blocked by a firewall)"
            )

        response_text = data.decode("utf-8", errors="replace")
        headers: dict[str, str] = {}
        for line in response_text.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        if not headers.get("st"):
            return [
                _not_tested_finding(
                    self.name,
                    "the SSDP response did not include a response type",
                    device.ip,
                )
            ], f"not tested: SSDP response from {device.ip} had no response type"

        igd_result: bool | None = None
        location = headers.get("location")
        if location:
            igd_result = _fetch_igd_description(location, device.ip)
        igd_status = (
            "InternetGatewayDevice: yes"
            if igd_result is True
            else "InternetGatewayDevice: no"
            if igd_result is False
            else "InternetGatewayDevice: unavailable"
        )

        if device.is_gateway:
            severity = Severity.MEDIUM
            title = f"UPnP/SSDP discovery responding on gateway ({device.ip})"
            details = (
                "The gateway responded to UPnP/SSDP discovery. This confirms that a local discovery service is "
                f"responding ({igd_status}). A device description can identify an InternetGatewayDevice, "
                "but this does not confirm that WAN port mappings are available."
            )
            recommendation = (
                "Unless you explicitly require UPnP for gaming consoles or specific media devices, "
                "consider disabling it in your router's administration settings to reduce the chance of "
                "unwanted automatic port forwarding."
            )
        else:
            severity = Severity.LOW
            title = f"UPnP/SSDP discovery responding on {device.ip}"
            details = (
                "The device responded to UPnP/SSDP discovery requests. UPnP on a client device (such as a TV, "
                f"printer, or media streamer) allows local discovery on your LAN. {igd_status}."
            )
            recommendation = (
                "Review the device's network settings. If local media sharing and discovery are unused, "
                "turn off UPnP/DLNA on this device."
            )

        return [
            Finding(
                name=self.name,
                title=title,
                description=details,
                severity=severity,
                recommendation=recommendation,
                evidence=[
                    "UDP port 1900 answered an SSDP M-SEARCH probe",
                    igd_status,
                ],
            )
        ], f"SSDP response from {device.ip} (ST: {answered_st or headers['st']}; {igd_status})"


def _fetch_igd_description(location: str, target_ip: str) -> bool | None:
    try:
        parsed = urlsplit(location)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(target_ip):
            return None
        request = urllib.request.Request(
            location, headers={"User-Agent": "netwatch/0.3"}
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=2.0) as response:
            description = response.read(65536).decode("utf-8", errors="replace")
        return bool(
            re.search(
                r"<deviceType>\s*urn:schemas-upnp-org:device:InternetGatewayDevice:",
                description,
                re.IGNORECASE,
            )
        )
    except (ValueError, urllib.error.URLError, OSError, TimeoutError):
        return None


KNOWN_PUBLIC_RESOLVERS = {
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare
    "8.8.8.8",
    "8.8.4.4",  # Google
    "9.9.9.9",
    "149.112.112.112",  # Quad9
    "208.67.222.222",
    "208.67.220.220",  # OpenDNS
    "94.140.14.14",
    "94.140.15.15",  # AdGuard
    "76.76.2.0",
    "76.76.10.0",  # Control D
    "185.228.168.9",
    "185.228.169.9",  # CleanBrowsing
}


def _interface_for_network(
    network: str,
) -> tuple[str, str] | None:
    target = ipaddress.ip_network(network, strict=False)
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            try:
                local_ip = ipaddress.ip_address(address.address)
            except ValueError:
                continue
            if local_ip in target:
                return name, str(local_ip)
    return None


def _get_interface_dns_resolvers(network: str) -> list[str]:
    adapter = _interface_for_network(network)
    if adapter is None:
        return []
    interface, _local_ip = adapter
    resolvers: list[str] = []
    if sys.platform.startswith("win"):
        command = (
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                rows = json.loads(completed.stdout)
                for row in rows if isinstance(rows, list) else [rows]:
                    if not isinstance(row, dict) or str(
                        row.get("InterfaceAlias", "")
                    ).casefold() != interface.casefold():
                        continue
                    values = row.get("ServerAddresses") or []
                    resolvers.extend(
                        [values] if isinstance(values, str) else values
                    )
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    elif sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                try:
                    interface_index = socket.if_nametoindex(interface)
                except OSError:
                    interface_index = -1
                for section in re.split(r"(?=resolver #\d+)", completed.stdout):
                    if (
                        f"({interface})" not in section
                        and not re.search(
                            rf"if_index\s*:\s*{interface_index}\b", section
                        )
                    ):
                        continue
                    resolvers.extend(
                        re.findall(
                            r"nameserver\[\d+\]\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                            section,
                        )
                    )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            completed = subprocess.run(
                ["resolvectl", "dns", interface],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                resolvers = re.findall(
                    r"\b\d{1,3}(?:\.\d{1,3}){3}\b", completed.stdout
                )
        except (OSError, subprocess.TimeoutExpired):
            pass

    return list(dict.fromkeys(resolvers))


def _get_system_dns_resolvers(network: str | None = None) -> list[str]:
    if network is not None:
        return _get_interface_dns_resolvers(network)
    resolvers: list[str] = []
    if sys.platform.startswith("win"):
        try:
            completed = subprocess.run(
                ["netsh", "interface", "ip", "show", "config"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    if "DNS servers" in line:
                        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if match:
                            resolvers.append(match.group(1))
                    elif re.match(r"^\s+(\d{1,3}(?:\.\d{1,3}){3})", line):
                        match = re.match(r"^\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if match:
                            resolvers.append(match.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                for match in re.finditer(
                    r"nameserver\[\d+\]\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                    completed.stdout,
                ):
                    resolvers.append(match.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        # Linux: check /run/systemd/resolve/resolv.conf first to bypass loopback stub
        stub_resolv = Path("/run/systemd/resolve/resolv.conf")
        content = ""
        if stub_resolv.exists():
            try:
                content = stub_resolv.read_text()
            except OSError:
                pass
        if not content:
            etc_resolv = Path("/etc/resolv.conf")
            if etc_resolv.exists():
                try:
                    content = etc_resolv.read_text()
                except OSError:
                    pass
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    resolvers.append(parts[1])

    if sys.platform.startswith("linux") and (
        not resolvers or all(r.startswith("127.") for r in resolvers)
    ):
        try:
            completed = subprocess.run(
                ["resolvectl", "dns"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                found = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", completed.stdout)
                if found:
                    resolvers = [ip for ip in found if not ip.startswith("127.")]
        except (OSError, subprocess.TimeoutExpired):
            pass

    seen: set[str] = set()
    result: list[str] = []
    for r in resolvers:
        if r not in seen:
            seen.add(r)
            result.append(r)
    return result


class RouterDNSCheck:
    name = "router_dns"
    description = "Checks system-configured resolvers for unexpected values; this is a heuristic, not a DHCP inspection."

    def __init__(
        self,
        expected_dns: list[str] | None = None,
        network: str | None = None,
    ) -> None:
        self.expected_dns = expected_dns
        self.network = network

    def run(self, device: Device) -> list[Finding]:
        findings, _status = self.run_with_result(device)
        return findings

    def run_with_result(self, device: Device) -> tuple[list[Finding], str]:
        if not device.is_gateway:
            return [], f"not tested: {device.ip} is not the gateway"

        resolvers = (
            _get_system_dns_resolvers(self.network)
            if self.network
            else _get_system_dns_resolvers()
        )
        findings: list[Finding] = []
        expected = set(self.expected_dns) if self.expected_dns else set()
        parsed_resolvers: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

        for dns_ip in resolvers:
            try:
                ip_obj = ipaddress.ip_address(dns_ip)
            except ValueError:
                continue
            parsed_resolvers.append(ip_obj)

            if ip_obj.is_loopback:
                continue

            if dns_ip in expected:
                continue

            if expected:
                findings.append(
                    Finding(
                        name=self.name,
                        title=f"Configured DNS resolver {dns_ip} differs from expected resolvers",
                        description=(
                            f"Resolver {dns_ip}, configured on this machine, does not match your expected DNS resolvers "
                            f"({', '.join(sorted(expected))}). This check cannot determine whether the resolver came "
                            "from the router, DHCP, or a manual operating-system setting."
                        ),
                        severity=Severity.HIGH,
                        recommendation="Confirm whether this resolver is expected in your operating-system and router DNS settings.",
                        evidence=[
                            f"Resolver {dns_ip} is active and not in expected_dns"
                        ],
                    )
                )
            elif (
                not ip_obj.is_private
                and dns_ip != device.ip
                and dns_ip not in KNOWN_PUBLIC_RESOLVERS
            ):
                findings.append(
                    Finding(
                        name=self.name,
                        title=f"Unrecognized public DNS resolver in use: {dns_ip}",
                        description=(
                            f"Your network is configured with public DNS resolver {dns_ip}, which is not in the list of "
                            "well-known public resolvers. Home networks typically use their router (LAN IP), a recognized "
                            "public resolver, or their ISP's DNS."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=f"Verify whether {dns_ip} belongs to your Internet Service Provider (ISP). If not recognized, configure trusted resolvers such as Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) on your router.",
                        evidence=[
                            f"Resolver {dns_ip} is active and not a recognized public resolver"
                        ],
                    )
                )

        if (
            parsed_resolvers
            and not findings
            and all(resolver.is_loopback for resolver in parsed_resolvers)
        ):
            return (
                [
                    _not_tested_finding(
                        self.name,
                        "the system uses a loopback DNS stub, so its upstream resolver cannot be determined",
                        device.ip,
                    )
                ],
                f"not tested: loopback DNS stub on {device.ip}; upstream resolver cannot be determined",
            )
        if not parsed_resolvers:
            return [
                _not_tested_finding(
                    self.name, "no system DNS resolver could be determined", device.ip
                )
            ], f"not tested: no system DNS resolver could be determined for {device.ip}"
        if findings:
            return findings, f"resolver findings for {device.ip}: " + "; ".join(
                f.title for f in findings
            )
        resolver_list = ", ".join(str(resolver) for resolver in parsed_resolvers)
        return [], f"resolvers {resolver_list} look expected for gateway {device.ip}"


DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
)


def _try_basic_auth(url: str, user: str, pw: str, timeout: float = 3.0) -> int:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth_bytes = f"{user}:{pw}".encode()
    auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {auth_b64}",
            "User-Agent": "netwatch/0.3",
        },
    )
    opener = _router_http_opener(ctx)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, ConnectionResetError, OSError):
        return -1


class RouterDefaultCredsCheck:
    name = "router_default_creds"
    description = (
        "Tests a small set of factory defaults on the gateway HTTP Basic Auth interface; "
        "requires explicit --check-creds opt-in."
    )

    def __init__(
        self,
        enabled: bool = False,
        delay_seconds: float = 1.0,
        target_ports: Sequence[int] | None = None,
    ) -> None:
        self.enabled = enabled
        self.delay_seconds = delay_seconds
        self.target_ports = (
            list(target_ports) if target_ports is not None else [80, 443, 8080, 8443]
        )

    def run(self, device: Device) -> list[Finding]:
        if not self.enabled:
            return []
        if not device.is_gateway:
            return []

        try:
            ip_obj = ipaddress.ip_address(device.ip)
        except ValueError:
            return [
                _not_tested_finding(
                    self.name, "the gateway IP address is invalid", device.ip
                )
            ]

        if not (ip_obj.is_private or ip_obj.is_loopback):
            return [
                _not_tested_finding(
                    self.name,
                    "the gateway is not a private or loopback address",
                    device.ip,
                )
            ]

        candidate_ports = [p for p in self.target_ports if p in device.open_ports]
        if not candidate_ports:
            return [
                _not_tested_finding(
                    self.name,
                    "no supported gateway administration port was observed",
                    device.ip,
                )
            ]

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        findings: list[Finding] = []

        for port in candidate_ports:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{device.ip}:{port}/"

            req = urllib.request.Request(url, headers={"User-Agent": "netwatch/0.3"})
            is_basic_auth = False
            baseline_status = None
            try:
                with _router_http_opener(ctx).open(req, timeout=3.0) as resp:
                    baseline_status = resp.status
            except urllib.error.HTTPError as exc:
                baseline_status = exc.code
                auth_header = exc.headers.get("WWW-Authenticate", "")
                if re.search(r"(?:^|,)\s*basic(?:\s|$)", auth_header, re.IGNORECASE):
                    is_basic_auth = True
            except (urllib.error.URLError, ConnectionResetError, OSError):
                continue

            if not is_basic_auth:
                findings.append(
                    Finding(
                        name=self.name,
                        title=f"Not tested: default-login test not supported for this login type ({device.ip}:{port})",
                        description=(
                            f"not tested: default-login test not supported for this login type on port {port}. "
                            "An unauthenticated request did not receive an HTTP 401 Basic Auth challenge."
                        ),
                        severity=Severity.INFO,
                        recommendation=(
                            "Log into your router's administration interface in your browser and confirm that the "
                            "default factory password has been changed to a strong, unique password."
                        ),
                        evidence=[
                            f"Unauthenticated request returned status {baseline_status} without Basic Auth challenge"
                        ],
                    )
                )
                continue

            if scheme == "http" and not ip_obj.is_loopback:
                findings.append(
                    Finding(
                        name=self.name,
                        title=f"Default-login test skipped on unencrypted interface {device.ip}:{port}",
                        description=(
                            "The gateway uses HTTP Basic Authentication over an unencrypted connection. "
                            "Netwatch did not send any credentials because they would be exposed in plaintext."
                        ),
                        severity=Severity.INFO,
                        recommendation=(
                            "Use the router's HTTPS administration interface if available. Otherwise, verify manually "
                            "that the factory administrator password has been changed."
                        ),
                        evidence=[
                            f"HTTP Basic Authentication challenge observed on port {port}; credential test skipped"
                        ],
                    )
                )
                continue

            accepted = False
            aborted_reason: str | None = None
            for attempt, (user, pw) in enumerate(DEFAULT_CREDS[:7]):
                status = _try_basic_auth(url, user, pw, timeout=3.0)
                if 200 <= status < 300:
                    accepted = True
                    break
                elif status in (403, 423, 429) or status == -1:
                    aborted_reason = (
                        "the server signaled a refusal or lockout"
                        if status in (403, 423, 429)
                        else "the connection failed or was reset"
                    )
                    break
                if self.delay_seconds > 0 and attempt + 1 < min(len(DEFAULT_CREDS), 7):
                    time.sleep(self.delay_seconds)

            if accepted:
                findings.append(
                    Finding(
                        name=self.name,
                        title=f"Default router credentials accepted on {device.ip}:{port}",
                        description=(
                            "Your router accepted a standard factory default administrator login. "
                            "Anyone on your local network can take full administrative control of your network."
                        ),
                        severity=Severity.CRITICAL,
                        recommendation=(
                            "Log into your router's administration page immediately and change the administrator "
                            "login secret to a strong, unique value."
                        ),
                        evidence=[
                            f"HTTP Basic Authentication on port {port} accepted factory default credentials."
                        ],
                    )
                )
                break
            if aborted_reason:
                findings.append(
                    _not_tested_finding(
                        self.name,
                        f"credential attempts stopped because {aborted_reason}",
                        device.ip,
                    )
                )
                break

        return findings


CHECKS: tuple[Check, ...] = (
    NewDeviceCheck(),
    ReachableServiceCheck(
        name="ftp_open",
        port=21,
        title="FTP is reachable",
        severity=Severity.MEDIUM,
        description="FTP service accepted a TCP connection.",
        recommendation=(
            "FTP may send credentials without encryption. Disable it if unused, or use an encrypted file-transfer service."
        ),
    ),
    ReachableServiceCheck(
        name="telnet_open",
        port=23,
        title="Telnet is reachable",
        severity=Severity.HIGH,
        description="Telnet service accepted a TCP connection.",
        recommendation=(
            "Telnet sends login credentials and sessions in plaintext. Disable it and use a secure administration method."
        ),
    ),
    ReachableServiceCheck(
        name="smb_exposed",
        port=445,
        title="SMB file sharing is reachable",
        severity=Severity.MEDIUM,
        description="SMB accepted a TCP connection from this machine.",
        recommendation=(
            "SMB can be expected on a trusted home LAN. Disable sharing if unused and ensure the firewall blocks it on public networks."
        ),
    ),
    ReachableServiceCheck(
        name="rtsp_open",
        port=554,
        title="RTSP media service is reachable",
        severity=Severity.MEDIUM,
        description="An RTSP-associated TCP port accepted a connection; authentication was not tested.",
        recommendation=(
            "If this is a camera or media device, review its access controls and avoid exposing the stream beyond your trusted LAN."
        ),
    ),
    ReachableServiceCheck(
        name="mqtt_open",
        port=1883,
        title="Unencrypted MQTT service is reachable",
        severity=Severity.MEDIUM,
        description="An MQTT-associated TCP port accepted a connection; credentials and broker policy were not tested.",
        recommendation=(
            "If this broker is needed, require authentication, restrict clients, and prefer TLS where supported."
        ),
    ),
    ReachableServiceCheck(
        name="rdp_open",
        port=3389,
        title="Remote Desktop is reachable",
        severity=Severity.MEDIUM,
        description="Remote Desktop accepted a TCP connection from this machine.",
        recommendation=(
            "Remote Desktop may be intentional on a home LAN. Turn it off if unused and never expose it directly to the internet."
        ),
    ),
    ReachableServiceCheck(
        name="plain_http",
        port=80,
        title="Unencrypted HTTP response observed",
        severity=Severity.LOW,
        description=(
            "The device returned an HTTP response over a connection without TLS. "
            "This does not verify that the service is an administration page."
        ),
        recommendation=(
            "Avoid entering passwords or sensitive information over this service. If it is device administration, use HTTPS if available."
        ),
        requires_http_banner=True,
    ),
    ReachableServiceCheck(
        name="plain_http_alt",
        port=8080,
        title="Unencrypted HTTP response observed on an alternate port",
        severity=Severity.LOW,
        description=(
            "The device returned an HTTP response over an alternate TCP port without TLS. "
            "This does not verify that the service is an administration page."
        ),
        recommendation=(
            "Confirm what is running on this port. Avoid sending credentials unless the service uses HTTPS."
        ),
        requires_http_banner=True,
    ),
    RouterUPnPCheck(),
    RouterDNSCheck(),
    RouterDefaultCredsCheck(),
)


def _filter_ignored_findings(
    findings: list[Finding],
    ignore_rules: list[dict[str, str]] | None,
) -> list[Finding]:
    if not ignore_rules:
        return findings

    filtered: list[Finding] = []
    for finding in findings:
        should_ignore = False
        for rule in ignore_rules:
            check_name = str(rule.get("check") or "").strip()
            if not check_name or finding.name != check_name:
                continue
            target = str(rule.get("target") or "").strip()
            if not target or finding.target == target:
                should_ignore = True
                break
        if not should_ignore:
            filtered.append(finding)
    return filtered


def add_findings(
    result: ScanResult,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    check_creds: bool = False,
    expected_dns: list[str] | None = None,
    ignore: list[dict[str, str]] | None = None,
) -> None:
    registered = {check.name: check for check in CHECKS}
    selected = set(only) if only else set(registered)
    excluded = set(skip or ())
    unknown = (selected | excluded) - set(registered)
    if unknown:
        raise ValueError(f"Unknown check name(s): {', '.join(sorted(unknown))}")

    creds_opted_in = check_creds
    result.checks_run = []
    result.skipped_checks = {}
    result.check_results = []

    def record_skip(name: str, reason: str) -> None:
        result.skipped_checks[name] = reason
        if name.startswith("router_"):
            result.check_results.append(f"{name}: skipped - {reason}")

    def add_check_finding(finding: Finding) -> None:
        if finding.title.startswith("Not tested:"):
            result.not_tested.append(
                NotTested(
                    name=finding.name,
                    reason=finding.description.removeprefix("not tested: ").rstrip("."),
                    target=finding.target,
                )
            )
        else:
            result.findings.append(finding)

    for check in CHECKS:
        if check.name not in selected:
            record_skip(check.name, "not selected by --only")
            continue
        if check.name in excluded:
            record_skip(check.name, "excluded by --skip")
            continue
        if check.name == "router_default_creds" and not creds_opted_in:
            record_skip(check.name, "opt-in required: pass --check-creds")
            continue

        if not result.devices:
            reason = "no devices were discovered"
            record_skip(check.name, reason)
            result.not_tested.append(NotTested(name=check.name, reason=reason))
            continue

        active_check = check
        if check.name == "router_default_creds" and isinstance(
            check, RouterDefaultCredsCheck
        ):
            active_check = RouterDefaultCredsCheck(
                enabled=True,
                delay_seconds=check.delay_seconds,
                target_ports=check.target_ports,
            )
        if check.name == "router_upnp" and isinstance(check, RouterUPnPCheck):
            adapter = _interface_for_network(result.cidr) if result.cidr else None
            active_check = RouterUPnPCheck(
                timeout=check.timeout,
                interface_ip=adapter[1] if adapter else None,
            )
        if check.name == "router_dns" and isinstance(check, RouterDNSCheck):
            active_check = RouterDNSCheck(expected_dns=expected_dns, network=result.cidr)

        if check.name in {"router_dns", "router_default_creds"}:
            targets = [device for device in result.devices if device.is_gateway]
            if not targets:
                reason = "no gateway was identified"
                record_skip(check.name, reason)
                result.not_tested.append(NotTested(name=check.name, reason=reason))
                continue
        elif check.name == "router_upnp":
            targets = []
            for device in result.devices:
                try:
                    address = ipaddress.ip_address(device.ip)
                except ValueError:
                    continue
                if (address.is_private or address.is_loopback) and not device.is_local:
                    targets.append(device)
            if not targets:
                reason = "no private or loopback non-local device was available for SSDP discovery"
                record_skip(check.name, reason)
                result.not_tested.append(NotTested(name=check.name, reason=reason))
                continue
        else:
            targets = result.devices

        result.checks_run.append(check.name)
        for device in targets:
            if (
                check.name == "router_upnp"
                and isinstance(active_check, RouterUPnPCheck)
                or check.name == "router_dns"
                and isinstance(active_check, RouterDNSCheck)
            ):
                findings, status = active_check.run_with_result(device)
                result.check_results.append(f"{check.name}: {status}")
            else:
                findings = active_check.run(device)
                if check.name == "router_default_creds":
                    if findings:
                        status = "; ".join(f.title for f in findings)
                    else:
                        status = f"no factory default credentials accepted on gateway {device.ip}"
                    result.check_results.append(f"{check.name}: {status}")
            for finding in findings:
                finding.target = device.ip
                add_check_finding(finding)

    result.findings = _filter_ignored_findings(result.findings, ignore)
