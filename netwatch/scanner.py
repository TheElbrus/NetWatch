from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import warnings
from datetime import UTC, datetime
from pathlib import Path

import psutil

from .models import Device, NetworkConfig, ScanResult

TOP_100_PORTS = (
    7,
    9,
    13,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    123,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    500,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1110,
    1433,
    1720,
    1723,
    1755,
    1883,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    5000,
    5001,
    5003,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    5901,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
)
MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")


class NetworkScopeError(ValueError):
    """Raised when a scan target is invalid or outside the allowed scope."""


def parse_target(
    config: NetworkConfig,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, list[int]]:
    try:
        network = ipaddress.ip_network(config.cidr, strict=False)
    except ValueError as exc:
        raise NetworkScopeError(f"Invalid CIDR: {config.cidr}") from exc

    if network.num_addresses > 4096:
        raise NetworkScopeError("Refusing to scan networks larger than 4096 addresses.")
    if not config.allow_public and not (network.is_private or network.is_loopback):
        raise NetworkScopeError(
            "Refusing to scan a public network. Use a private LAN CIDR or explicitly pass --allow-public."
        )

    return network, parse_ports(config.ports)


def parse_ports(value: str) -> list[int]:
    if value == "top100":
        return list(TOP_100_PORTS)
    if value == "top1000":
        return list(range(1, 1001))
    try:
        ports = sorted({int(part.strip()) for part in value.split(",") if part.strip()})
    except ValueError as exc:
        raise NetworkScopeError(
            "Ports must be top100, top1000, or a comma-separated list of numbers."
        ) from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise NetworkScopeError("Port numbers must be between 1 and 65535.")
    return ports


def _is_tunnel_interface(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return any(
        token in lowered
        for token in (
            "xray",
            "tun",
            "tap",
            "vpn",
            "wireguard",
            "tailscale",
            "zerotier",
            "docker",
            "vbox",
            "virtualbox",
            "vmware",
            "hyper-v",
        )
    )


def _list_ip_routes() -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []

    if sys.platform.startswith("win"):
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, InterfaceAlias | ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return routes
        if completed.returncode != 0 or not completed.stdout.strip():
            return routes
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return routes
        rows = payload if isinstance(payload, list) else [payload]
        for route in rows:
            if not isinstance(route, dict):
                continue
            destination = route.get("DestinationPrefix") or route.get("Destination")
            interface = route.get("InterfaceAlias") or route.get("Interface")
            if destination:
                routes.append(
                    {"destination": str(destination), "interface": str(interface or "")}
                )
        return routes

    if sys.platform == "darwin":
        command = ["netstat", "-rn", "-f", "inet"]
    else:
        command = ["ip", "route", "show"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return routes

    if completed.returncode != 0:
        return routes
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if sys.platform == "darwin":
            if stripped.startswith("default"):
                parts = stripped.split()
                if len(parts) >= 8:
                    destination = "0.0.0.0/0"
                    interface = parts[-1]
                    routes.append({"destination": destination, "interface": interface})
            continue
        if stripped.startswith("default"):
            if " via " not in stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 5 and "dev" in parts:
                dev_index = parts.index("dev") + 1
                routes.append(
                    {"destination": "0.0.0.0/0", "interface": parts[dev_index]}
                )
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        destination = parts[0]
        if "via" in parts:
            via_index = parts.index("via") + 1
            if via_index < len(parts):
                pass
        if destination.count(".") != 3 and "/" not in destination:
            continue
        interface = ""
        if "dev" in parts:
            dev_index = parts.index("dev") + 1
            if dev_index < len(parts):
                interface = parts[dev_index]
        if destination:
            routes.append({"destination": destination, "interface": interface})
    return routes


def _validate_route_for_network(
    network: ipaddress.IPv4Network, interface: str | None = None
) -> None:
    routes = _list_ip_routes()
    if not routes:
        return

    candidates: list[tuple[int, str, str]] = []
    for route in routes:
        destination = route.get("destination", "")
        route_interface = route.get("interface", "")
        if not destination:
            continue
        try:
            route_network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version != route_network.version:
            continue
        if interface is not None and route_interface.lower() != interface.lower():
            continue
        if (
            network.subnet_of(route_network)
            or route_network.subnet_of(network)
            or network.overlaps(route_network)
        ):
            candidates.append((route_network.prefixlen, route_interface, destination))

    if not candidates:
        return

    best_prefix, best_interface, _best_destination = max(
        candidates, key=lambda item: item[0]
    )
    if best_prefix == 0 and _is_tunnel_interface(best_interface):
        raise NetworkScopeError(
            "The active default route for this target is using a tunnel or VPN interface (for example xray_tun). "
            "Choose the physical LAN interface or disable the tunnel before scanning."
        )

    if interface is not None and _is_tunnel_interface(best_interface):
        raise NetworkScopeError(
            f"Interface '{interface}' does not appear to be a LAN route for {network}. "
            "The selected route is through a tunnel or VPN interface."
        )


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> tuple[bool, str | None]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except (TimeoutError, OSError):
            return False, None

        banner = None
        try:
            if port in {80, 81, 8000, 8008, 8080, 8081, 8888}:
                writer.write(
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode(
                        "ascii"
                    )
                )
                await writer.drain()
                data = await asyncio.wait_for(
                    reader.read(1024), timeout=min(timeout, 0.75)
                )
                banner = _sanitize_banner(data)
            else:
                data = await asyncio.wait_for(
                    reader.read(512), timeout=min(timeout, 0.35)
                )
                banner = _sanitize_banner(data)
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True, banner


TELNET_IAC_PATTERN = re.compile(
    rb"\xff(?:\xfa.*?\xff\xf0|[\xfb-\xfe][\x00-\xff]|[\xf0-\xfa]|\xff)"
)


def _clean_telnet_bytes(data: bytes) -> bytes:
    if b"\xff" not in data:
        return data
    return TELNET_IAC_PATTERN.sub(b"", data)


def _is_valid_mac(mac: str | None) -> bool:
    if not mac:
        return False
    normalized = mac.lower().replace("-", ":")
    if not MAC_PATTERN.fullmatch(normalized):
        return False
    if normalized in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return False
    first_octet = int(normalized.split(":", 1)[0], 16)
    return (first_octet & 1) == 0


def _sanitize_banner(data: bytes) -> str | None:
    if not data:
        return None
    data = _clean_telnet_bytes(data)
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").replace("\ufffd", "")
    if text.upper().startswith("HTTP/"):
        headers = text.split("\r\n\r\n", 1)[0].splitlines()
        selected = headers[:1] + [
            line for line in headers[1:] if line.lower().startswith("server:")
        ]
        text = "\r\n".join(selected)
    lines = [
        "".join(character for character in line if character.isprintable()).strip()
        for line in text.splitlines()
    ]
    banner = " | ".join(line for line in lines if line)
    if not banner or not any(character.isalnum() for character in banner):
        return None
    return banner[:300] or None


class _NoFingerprintRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fingerprint_gateway(device: Device, timeout: float = 3.0) -> dict[str, str]:
    try:
        address = ipaddress.ip_address(device.ip)
    except ValueError:
        return {}
    if not (address.is_private or address.is_loopback):
        return {}

    fingerprint: dict[str, str] = {}
    http_ports = {
        80: "http",
        81: "http",
        8000: "http",
        8008: "http",
        8080: "http",
        8081: "http",
        8888: "http",
        443: "https",
        8443: "https",
    }
    web_port = next((port for port in http_ports if port in device.open_ports), None)
    if web_port is not None:
        url_host = f"[{device.ip}]" if address.version == 6 else device.ip
        url = f"{http_ports[web_port]}://{url_host}:{web_port}/"
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoFingerprintRedirectHandler(),
        )
        for attempt in range(3):
            response = None
            try:
                request = urllib.request.Request(
                    url,
                    headers={"User-Agent": "netwatch/0.3", "Connection": "close"},
                )
                response = opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                reason = getattr(exc, "reason", exc)
                fingerprint["http_title_error"] = (
                    "timed out"
                    if isinstance(reason, (TimeoutError, socket.timeout))
                    else "request failed"
                )
            if response is not None:
                try:
                    server = response.headers.get("Server")
                    if server:
                        fingerprint["server"] = server[:200]
                    page = response.read(65536).decode("utf-8", errors="replace")
                    title_match = re.search(
                        r"<title\b[^>]*>(.*?)</title\s*>",
                        page,
                        re.IGNORECASE | re.DOTALL,
                    )
                    if title_match:
                        title = re.sub(
                            r"\s+", " ", re.sub(r"<[^>]+>", "", title_match.group(1))
                        ).strip()
                        if title:
                            fingerprint["http_title"] = title[:200]
                            fingerprint.pop("http_title_error", None)
                            break
                    fingerprint["http_title_error"] = "page title not found"
                except (urllib.error.URLError, OSError, TimeoutError) as exc:
                    fingerprint["http_title_error"] = (
                        "timed out" if isinstance(exc, (TimeoutError, socket.timeout)) else "response failed"
                    )
                finally:
                    try:
                        response.close()
                    except OSError:
                        pass
            if attempt == 0:
                time.sleep(1.0)
            elif attempt == 1:
                time.sleep(1.0)

    if 23 in device.open_ports:
        try:
            with socket.create_connection((device.ip, 23), timeout=1.0) as connection:
                connection.settimeout(1.0)
                banner = _sanitize_banner(connection.recv(512))
                if banner:
                    fingerprint["telnet_banner"] = banner[:300]
        except (OSError, TimeoutError):
            pass
    return fingerprint


def collect_router_fingerprint(result: ScanResult) -> None:
    for device in result.devices:
        if device.is_gateway:
            device.router_fingerprint = _fingerprint_gateway(device)


async def _scan_host(
    ip: str,
    ports: list[int],
    timeout: float,
    port_semaphore: asyncio.Semaphore,
    host_semaphore: asyncio.Semaphore,
) -> tuple[list[int], dict[int, str]]:
    async with host_semaphore:
        results = await asyncio.gather(
            *(_probe_port(ip, port, timeout, port_semaphore) for port in ports)
        )
    open_ports = [port for port, (is_open, _banner) in zip(ports, results) if is_open]
    banners = {
        port: banner for port, (_is_open, banner) in zip(ports, results) if banner
    }
    return open_ports, banners


def _neighbor_macs(
    network: ipaddress.IPv4Network | None = None,
    timeout: float = 3,
) -> dict[str, str]:
    if sys.platform.startswith("win"):
        command = ["arp", "-a"]
    elif sys.platform == "darwin":
        command = ["arp", "-an"]
    else:
        command = ["ip", "neigh", "show"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        warnings.warn(
            f"Could not read the operating system's neighbor table: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}

    if completed.returncode != 0:
        warnings.warn(
            f"Could not read the operating system's neighbor table (exit code {completed.returncode}).",
            RuntimeWarning,
            stacklevel=2,
        )
    output = completed.stdout
    if sys.platform.startswith("win"):
        return _parse_windows_arp(output, network)

    neighbors: dict[str, str] = {}
    for line in output.splitlines():
        addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        macs = MAC_PATTERN.findall(line)
        if not addresses or not macs:
            continue
        try:
            address = ipaddress.ip_address(addresses[0])
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Address):
            continue
        if network is not None and address not in network:
            continue
        if (
            address.is_multicast
            or address.packed[-1] == 255
            or (network is not None and address == network.broadcast_address)
        ):
            continue
        ip = str(address)
        mac = macs[0].replace("-", ":").lower()
        if not _is_valid_mac(mac):
            continue
        neighbors[ip] = mac
    return neighbors


def _parse_windows_arp(
    output: str,
    network: ipaddress.IPv4Network | None = None,
) -> dict[str, str]:
    neighbors: dict[str, str] = {}
    interface_matches_network = True
    for line in output.splitlines():
        interface_match = re.search(
            r"(?i)\bInterface:\s*((?:\d{1,3}\.){3}\d{1,3})",
            line,
        )
        if interface_match:
            try:
                interface_ip = ipaddress.IPv4Address(interface_match.group(1))
            except ipaddress.AddressValueError:
                interface_matches_network = False
            else:
                interface_matches_network = network is None or interface_ip in network
            continue
        if not interface_matches_network:
            continue
        addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        macs = MAC_PATTERN.findall(line)
        if not addresses or not macs:
            continue
        try:
            address = ipaddress.IPv4Address(addresses[0])
        except ipaddress.AddressValueError:
            continue
        if network is not None and address not in network:
            continue
        if address.is_multicast or address.packed[-1] == 255:
            continue
        mac = macs[0].replace("-", ":").lower()
        if _is_valid_mac(mac):
            neighbors[str(address)] = mac
    return neighbors


def _arp_discover(
    network: ipaddress.IPv4Network,
    interface: str | None,
) -> dict[str, str] | None:
    if network.is_loopback:
        return None
    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]
        from scapy.error import Scapy_Exception
    except ImportError as exc:
        warnings.warn(
            f"Scapy is unavailable; using TCP-only discovery: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None

    try:
        answered, _unanswered = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            iface=interface,
            timeout=1.5,
            retry=1,
            verbose=0,
        )
    except (OSError, RuntimeError, ValueError, Scapy_Exception) as exc:
        reason = str(exc)
        if "winpcap is not installed" in reason.lower() or "pcap" in reason.lower():
            reason = "Npcap/WinPcap is not installed on Windows"
        if (
            "npcap" in reason.casefold()
            or "winpcap" in reason.casefold()
            or "pcap" in reason.casefold()
        ):
            print("Npcap not installed: using TCP sweep + ARP cache.")
        else:
            warnings.warn(
                f"ARP discovery could not run ({reason}); falling back to TCP reachability.",
                RuntimeWarning,
                stacklevel=2,
            )
        return None

    discovered: dict[str, str] = {}
    for _sent, received in answered:
        try:
            ip = str(ipaddress.ip_address(received.psrc))
            mac = str(received.hwsrc).replace("-", ":").lower()
        except (AttributeError, ValueError):
            continue
        discovered[ip] = mac
    return discovered


def _vendor_for_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import conf

        _short, vendor = conf.manufdb.lookup(mac)
    except (ImportError, AttributeError, ValueError):
        return None
    return vendor if vendor and vendor.lower() not in {"unknown", "unk"} else None


def _hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def _local_ipv4_addresses() -> set[str]:
    addresses: set[str] = set()
    for interface_addresses in psutil.net_if_addrs().values():
        for address in interface_addresses:
            if address.family != socket.AF_INET:
                continue
            try:
                addresses.add(str(ipaddress.ip_address(address.address)))
            except ValueError:
                continue
    return addresses


def _local_ipv4_networks() -> set[ipaddress.IPv4Network]:
    networks: set[ipaddress.IPv4Network] = set()
    for interface_addresses in psutil.net_if_addrs().values():
        for address in interface_addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            try:
                interface = ipaddress.ip_interface(
                    f"{address.address}/{address.netmask}"
                )
            except ValueError:
                continue
            if interface.ip.is_link_local or interface.ip.is_loopback:
                continue
            networks.add(interface.network)
    return networks


def _local_ipv4_macs() -> dict[str, str]:
    addresses: dict[str, str] = {}
    for interface_addresses in psutil.net_if_addrs().values():
        ipv4_addresses = [
            address.address
            for address in interface_addresses
            if address.family == socket.AF_INET
        ]
        link_addresses = [
            address.address
            for address in interface_addresses
            if address.family == psutil.AF_LINK
        ]
        for ipv4 in ipv4_addresses:
            try:
                ip = str(ipaddress.ip_address(ipv4))
            except ValueError:
                continue
            mac = next(
                (
                    address.replace("-", ":").lower()
                    for address in link_addresses
                    if _is_valid_mac(address)
                ),
                None,
            )
            if mac:
                addresses[ip] = mac
    return addresses


def _validate_on_link(network: ipaddress.IPv4Network) -> None:
    if network.is_loopback:
        return
    if any(
        network.subnet_of(local_network) for local_network in _local_ipv4_networks()
    ):
        return
    raise NetworkScopeError(
        f"This machine is not on {network}. Connect to that network (VPN off) and retry."
    )


def find_gateway_ip(network: ipaddress.IPv4Network | None = None) -> str | None:
    """Detect the default gateway IPv4 address defensively across Windows, macOS, and Linux.

    If a network is provided, only return a gateway that resides within that network.
    """
    candidates: list[tuple[str, str]] = []  # (gateway, interface)

    if sys.platform.startswith("win"):
        try:
            completed = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                for match in re.finditer(
                    r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
                    completed.stdout,
                ):
                    candidates.append((match.group(1), match.group(2)))
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode == 0:
                gw_match = re.search(
                    r"gateway:\s+(\d{1,3}(?:\.\d{1,3}){3})", completed.stdout
                )
                if gw_match:
                    candidates.append((gw_match.group(1), ""))
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        # Linux: try /proc/net/route first
        route_file = Path("/proc/net/route")
        if route_file.exists():
            try:
                for line in route_file.read_text().splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        if len(gw_hex) == 8:
                            gw_ip = socket.inet_ntoa(struct.pack("<I", int(gw_hex, 16)))
                            candidates.append((gw_ip, parts[0]))
            except OSError:
                pass
        if not candidates:
            try:
                completed = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if completed.returncode == 0:
                    gw_match = re.search(
                        r"via\s+(\d{1,3}(?:\.\d{1,3}){3})", completed.stdout
                    )
                    if gw_match:
                        candidates.append((gw_match.group(1), ""))
            except (OSError, subprocess.TimeoutExpired):
                pass

    for gw_str, _iface in candidates:
        try:
            gw_addr = ipaddress.ip_address(gw_str)
        except ValueError:
            continue
        if network is not None and gw_addr not in network:
            continue
        return str(gw_addr)

    return None


def discover_devices(config: NetworkConfig) -> ScanResult:
    network, ports = parse_target(config)
    if network.version != 4:
        raise NetworkScopeError("IPv6 scanning is not supported yet.")
    _validate_on_link(network)
    _validate_route_for_network(network, config.interface)

    addresses = [str(ip) for ip in network.hosts()]
    if network.prefixlen == 32:
        addresses = [str(network.network_address)]
    if not addresses:
        raise NetworkScopeError(
            "The selected network contains no scannable host addresses."
        )
    if config.timeout <= 0:
        raise NetworkScopeError("Timeout must be greater than zero.")
    if config.concurrency < 1:
        raise NetworkScopeError("Concurrency must be at least 1.")

    neighbor_macs = _neighbor_macs()
    arp_macs = _arp_discover(network, config.interface)
    if arp_macs is None or not arp_macs:
        if arp_macs == {}:
            warnings.warn(
                "ARP discovery received no replies; falling back to TCP reachability.",
                RuntimeWarning,
                stacklevel=2,
            )
        scan_addresses = addresses
        discovery_method = "tcp_fallback"
    else:
        neighbor_macs.update(arp_macs)
        scan_addresses = sorted(arp_macs, key=ipaddress.ip_address)
        discovery_method = "arp"

    async def scan_all() -> list[tuple[list[int], dict[int, str]]]:
        port_semaphore = asyncio.Semaphore(config.concurrency)
        host_semaphore = asyncio.Semaphore(min(config.concurrency, 16))
        return list(
            await asyncio.gather(
                *(
                    _scan_host(
                        ip,
                        ports,
                        config.timeout,
                        port_semaphore,
                        host_semaphore,
                    )
                    for ip in scan_addresses
                )
            )
        )

    opened = asyncio.run(scan_all())
    discovered = list(zip(scan_addresses, opened))

    if discovery_method == "tcp_fallback":
        cached_macs = _neighbor_macs(network=network, timeout=5)
        neighbor_macs = cached_macs
        discovered = [
            (ip, (open_ports, banners))
            for ip, (open_ports, banners) in discovered
            if open_ports or ip in neighbor_macs
        ]
        discovered_ips = {ip for ip, _observations in discovered}
        discovered.extend(
            (ip, ([], {})) for ip in cached_macs if ip not in discovered_ips
        )
        discovery_method = "tcp_sweep+arp_cache"

    gateway_ip = find_gateway_ip(network)
    local_addresses = _local_ipv4_addresses()
    local_macs = _local_ipv4_macs()

    async def resolve_hostnames() -> list[str | None]:
        return list(
            await asyncio.gather(
                *(asyncio.to_thread(_hostname, ip) for ip, _ in discovered)
            )
        )

    hostnames = asyncio.run(resolve_hostnames()) if discovered else []
    result = ScanResult(
        timestamp=datetime.now(UTC),
        cidr=str(network),
        scanned_ports=ports,
        discovery_method=discovery_method,
        gateway_ip=gateway_ip,
    )
    for (ip, (open_ports, banners)), hostname in zip(discovered, hostnames):
        mac = neighbor_macs.get(ip) or (
            local_macs.get(ip) if ip in local_addresses else None
        )
        result.add_device(
            Device(
                ip=ip,
                mac=mac,
                vendor=_vendor_for_mac(mac),
                hostname=hostname,
                is_gateway=(ip == gateway_ip),
                is_local=(ip in local_addresses),
                last_seen=result.timestamp,
                open_ports=open_ports,
                banners=banners,
            )
        )
    return result
