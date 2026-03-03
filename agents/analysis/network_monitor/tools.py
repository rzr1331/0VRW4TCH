from __future__ import annotations

import re
import shutil
import subprocess
from datetime import UTC, datetime
from typing import Any, Dict, List

from .models import score_network_threat


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(command: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None


_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1",
    "fe80:", "fc00:", "fd00:",
)


def _is_private(ip: str) -> bool:
    ip = ip.strip().lower()
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _is_external(ip: str) -> bool:
    return bool(ip) and not _is_private(ip)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# TOOL 1 — Connection state inventory
# ---------------------------------------------------------------------------

def monitor_active_connections(max_connections: int = 300) -> Dict[str, Any]:
    """Enumerate all ESTABLISHED and LISTEN TCP/UDP connections.

    Uses ``ss`` (preferred on Linux) falling back to ``netstat`` (macOS/older
    Linux), then ``lsof -i`` as a last resort.

    Returns a dict with connections list, state counts, and external peer IPs.
    """
    connections: List[Dict[str, Any]] = []
    source = "unavailable"

    # --- Try ss (Linux) ---
    if shutil.which("ss") is not None:
        result = _run(["ss", "-tupnH"], timeout=5)
        if result is not None and result.returncode == 0:
            source = "ss"
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                proto = parts[0]
                state = parts[1]
                local = parts[4]
                remote = parts[5]
                pid_match = re.search(r"pid=(\d+)", line)
                proc_match = re.search(r'users:\(\("([^"]+)"', line)
                local_ip, _, local_port = local.rpartition(":")
                remote_ip, _, remote_port = remote.rpartition(":")
                connections.append({
                    "proto": proto, "state": state,
                    "local_addr": local_ip, "local_port": _safe_int(local_port),
                    "remote_addr": remote_ip, "remote_port": _safe_int(remote_port),
                    "pid": int(pid_match.group(1)) if pid_match else None,
                    "process": proc_match.group(1) if proc_match else None,
                })
                if len(connections) >= max_connections:
                    break

    # --- Fallback: netstat (macOS / older Linux) ---
    if not connections and shutil.which("netstat") is not None:
        result = _run(["netstat", "-anp", "tcp"], timeout=5)
        if result is None or result.returncode != 0:
            result = _run(["netstat", "-an"], timeout=5)
        if result is not None and result.returncode == 0:
            source = "netstat"
            for line in result.stdout.splitlines():
                if not line.strip() or line.startswith("Proto") or line.startswith("Active"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0]
                local = parts[3]
                remote = parts[4]
                state = parts[5] if len(parts) > 5 else "UNKNOWN"
                local_ip, _, local_port = local.rpartition(".")
                remote_ip, _, remote_port = remote.rpartition(".")
                connections.append({
                    "proto": proto, "state": state,
                    "local_addr": local_ip, "local_port": _safe_int(local_port),
                    "remote_addr": remote_ip, "remote_port": _safe_int(remote_port),
                    "pid": None, "process": None,
                })
                if len(connections) >= max_connections:
                    break

    # --- Last resort: lsof -i ---
    if not connections and shutil.which("lsof") is not None:
        result = _run(["lsof", "-nP", "-i", "-sTCP:ESTABLISHED"], timeout=6)
        if result is not None and result.returncode == 0:
            source = "lsof"
            for idx, line in enumerate(result.stdout.splitlines()):
                if idx == 0:
                    continue  # skip header
                parts = line.split()
                if len(parts) < 9:
                    continue
                command, pid_raw = parts[0], parts[1]
                name_field = parts[-1]
                state_match = re.search(r"\(([^)]+)\)", name_field)
                state = state_match.group(1) if state_match else "UNKNOWN"
                arrow_match = re.match(r"([^:]+):(\d+)->([^:]+):(\d+)", name_field)
                if arrow_match:
                    local_ip, local_port = arrow_match.group(1), arrow_match.group(2)
                    remote_ip, remote_port = arrow_match.group(3), arrow_match.group(4)
                else:
                    local_ip = local_port = remote_ip = remote_port = ""
                connections.append({
                    "proto": "tcp", "state": state,
                    "local_addr": local_ip, "local_port": _safe_int(local_port),
                    "remote_addr": remote_ip, "remote_port": _safe_int(remote_port),
                    "pid": int(pid_raw) if pid_raw.isdigit() else None,
                    "process": command,
                })
                if len(connections) >= max_connections:
                    break

    external_peers = sorted({
        c["remote_addr"] for c in connections
        if _is_external(str(c.get("remote_addr", "")))
    })
    state_counts: Dict[str, int] = {}
    for c in connections:
        s = str(c.get("state", "UNKNOWN"))
        state_counts[s] = state_counts.get(s, 0) + 1

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "source": source,
        "connections": connections[:max_connections],
        "total_connections": len(connections),
        "external_peers": external_peers[:100],
        "external_peer_count": len(external_peers),
        "state_counts": state_counts,
        "note": "Connection data is a point-in-time snapshot.",
    }


# ---------------------------------------------------------------------------
# TOOL 2 — Traffic volume analysis (bytes in/out per interface)
# ---------------------------------------------------------------------------

def analyze_traffic_volume() -> Dict[str, Any]:
    """Read per-interface byte counters from /proc/net/dev (Linux) or
    netstat -ib (macOS). Flags interfaces with unusually high egress.

    Returns per-interface stats and high-egress warnings.
    """
    interfaces: List[Dict[str, Any]] = []
    source = "unavailable"

    # Linux: /proc/net/dev
    try:
        with open("/proc/net/dev", "r") as fh:
            lines = fh.readlines()
        source = "/proc/net/dev"
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            interfaces.append({
                "interface": iface,
                "bytes_recv": int(parts[1]),
                "packets_recv": int(parts[2]),
                "errors_recv": int(parts[3]),
                "bytes_sent": int(parts[9]),
                "packets_sent": int(parts[10]),
                "errors_sent": int(parts[11]),
            })
    except (OSError, IndexError, ValueError):
        pass

    # macOS fallback: netstat -ib
    if not interfaces and shutil.which("netstat") is not None:
        result = _run(["netstat", "-ib"], timeout=4)
        if result is not None and result.returncode == 0:
            source = "netstat -ib"
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 10 or parts[0] == "Name":
                    continue
                iface = parts[0]
                if iface.startswith("lo"):
                    continue
                try:
                    interfaces.append({
                        "interface": iface,
                        "bytes_recv": int(parts[6]),
                        "packets_recv": int(parts[4]),
                        "errors_recv": int(parts[5]),
                        "bytes_sent": int(parts[9]),
                        "packets_sent": int(parts[7]),
                        "errors_sent": int(parts[8]),
                    })
                except (IndexError, ValueError):
                    continue

    HIGH_EGRESS_BYTES = 10 * 1024 ** 3  # 10 GB
    flagged = [
        iface for iface in interfaces
        if isinstance(iface.get("bytes_sent"), int) and iface["bytes_sent"] > HIGH_EGRESS_BYTES
    ]

    total_bytes_sent = sum(
        i.get("bytes_sent", 0) for i in interfaces if isinstance(i.get("bytes_sent"), int)
    )
    total_bytes_recv = sum(
        i.get("bytes_recv", 0) for i in interfaces if isinstance(i.get("bytes_recv"), int)
    )

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "source": source,
        "interfaces": interfaces,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_recv": total_bytes_recv,
        "total_sent_mb": round(total_bytes_sent / (1024 ** 2), 2),
        "total_recv_mb": round(total_bytes_recv / (1024 ** 2), 2),
        "high_egress_interfaces": flagged,
        "note": "Counters are cumulative since boot. High egress interfaces may warrant investigation.",
    }


# ---------------------------------------------------------------------------
# TOOL 3 — DNS analysis (hijacking, suspicious resolvers, /etc/hosts)
# ---------------------------------------------------------------------------

_KNOWN_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",                          # Google
    "1.1.1.1", "1.0.0.1",                          # Cloudflare
    "9.9.9.9",                                      # Quad9
    "208.67.222.222", "208.67.220.220",             # OpenDNS
}


def analyze_dns_behavior() -> Dict[str, Any]:
    """Probe DNS configuration for hijacking indicators.

    Checks:
    1. Resolver configuration (/etc/resolv.conf or scutil --dns on macOS)
    2. Sample DNS queries via dig/nslookup
    3. Suspicious /etc/hosts overrides
    """
    findings: List[Dict[str, Any]] = []
    resolvers: List[str] = []

    # Read resolver config
    try:
        with open("/etc/resolv.conf", "r") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1].strip())
    except OSError:
        pass

    # macOS: scutil --dns
    if not resolvers and shutil.which("scutil") is not None:
        result = _run(["scutil", "--dns"], timeout=4)
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                if "nameserver" in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if ip:
                            resolvers.append(ip)

    unknown_resolvers = [r for r in resolvers if r not in _KNOWN_RESOLVERS]
    if unknown_resolvers:
        findings.append({
            "signal_type": "unusual_dns_resolver",
            "severity": "medium",
            "description": f"DNS resolver(s) not in known-good set: {unknown_resolvers}",
            "indicators": {"resolvers": resolvers, "unknown": unknown_resolvers},
        })

    # Sample DNS queries
    test_domains = ["google.com", "github.com", "cloudflare.com"]
    dns_query_results: List[Dict[str, Any]] = []
    dig_available = shutil.which("dig") is not None
    nslookup_available = shutil.which("nslookup") is not None

    for domain in test_domains:
        if dig_available:
            result = _run(["dig", "+short", "+time=2", "+tries=1", domain], timeout=5)
            dns_query_results.append({
                "domain": domain,
                "tool": "dig",
                "output": (result.stdout.strip()[:200] if result and result.returncode == 0 else "failed"),
            })
        elif nslookup_available:
            result = _run(["nslookup", "-timeout=2", domain], timeout=5)
            dns_query_results.append({
                "domain": domain,
                "tool": "nslookup",
                "output": (result.stdout.strip()[:200] if result and result.returncode == 0 else "failed"),
            })

    # Inspect /etc/hosts for suspicious redirects
    suspicious_hosts: List[str] = []
    try:
        with open("/etc/hosts", "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    for hostname in parts[1:]:
                        if "." in hostname and not hostname.endswith(".local"):
                            suspicious_hosts.append(f"{parts[0]} {hostname}")
    except OSError:
        pass

    if suspicious_hosts:
        findings.append({
            "signal_type": "suspicious_hosts_entry",
            "severity": "medium",
            "description": f"Suspicious /etc/hosts entries: {len(suspicious_hosts)} non-local overrides",
            "indicators": {"entries": suspicious_hosts[:20]},
        })

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "resolvers": resolvers,
        "unknown_resolvers": unknown_resolvers,
        "dns_query_samples": dns_query_results,
        "suspicious_hosts_entries": suspicious_hosts[:20],
        "findings": findings,
        "note": "DNS analysis is heuristic; validate findings against DHCP/DNS policy.",
    }


# ---------------------------------------------------------------------------
# TOOL 4 — ARP table analysis (spoofing / MAC conflicts)
# ---------------------------------------------------------------------------

def analyze_arp_table() -> Dict[str, Any]:
    """Inspect the ARP table for duplicate IP-to-MAC mappings (spoofing
    indicator) and flag incomplete / failed entries.

    Uses ``arp -a`` on macOS/Linux.
    """
    findings: List[Dict[str, Any]] = []
    entries: List[Dict[str, Any]] = []

    if shutil.which("arp") is not None:
        result = _run(["arp", "-a", "-n"], timeout=4)
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
                mac_match = re.search(r"at\s+([0-9a-fA-F:]{17}|<incomplete>)", line)
                iface_match = re.search(r"on\s+(\S+)", line)
                if not ip_match:
                    continue
                entries.append({
                    "ip": ip_match.group(1),
                    "mac": mac_match.group(1) if mac_match else "unknown",
                    "interface": iface_match.group(1) if iface_match else "unknown",
                    "incomplete": "incomplete" in line.lower(),
                })

    # Detect duplicate IPs with different MACs
    ip_to_macs: Dict[str, set] = {}
    for entry in entries:
        mac = entry["mac"]
        if mac == "unknown" or entry.get("incomplete"):
            continue
        ip_to_macs.setdefault(entry["ip"], set()).add(mac)

    duplicate_ips = {ip: list(macs) for ip, macs in ip_to_macs.items() if len(macs) > 1}

    if duplicate_ips:
        for ip, macs in duplicate_ips.items():
            findings.append({
                "signal_type": "arp_spoofing",
                "severity": "high",
                "description": f"ARP spoofing detected: IP {ip} maps to multiple MACs: {macs}",
                "indicators": {"ip": ip, "mac_addresses": macs},
            })

    incomplete_count = sum(1 for e in entries if e.get("incomplete"))
    if incomplete_count > 20:
        findings.append({
            "signal_type": "arp_incomplete_flood",
            "severity": "medium",
            "description": f"High count of incomplete ARP entries ({incomplete_count}) may indicate network scanning.",
            "indicators": {"incomplete_count": incomplete_count},
        })

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "arp_entries": entries[:200],
        "total_entries": len(entries),
        "duplicate_ips": duplicate_ips,
        "duplicate_ip_count": len(duplicate_ips),
        "incomplete_count": incomplete_count,
        "findings": findings,
        "arp_available": shutil.which("arp") is not None,
    }


# ---------------------------------------------------------------------------
# TOOL 5 — Outbound connection analysis (exfiltration / C2 / abuse)
# ---------------------------------------------------------------------------

# Known-bad ports commonly used for C2 / IRC / shells
_SUSPICIOUS_OUTBOUND_PORTS = {
    4444, 4445, 1234, 31337, 6666, 6667, 6668, 6669,   # C2 / IRC
    9001, 9050, 9051,                                    # Tor
    2222, 2323, 5555, 7777, 8888,                        # Common reverse shells
}


def analyze_outbound_connections() -> Dict[str, Any]:
    """Analyze outbound (ESTABLISHED) connections for exfiltration, C2
    communication, and abuse patterns.

    Internally calls ``monitor_active_connections`` so the LLM does not need
    to chain them manually.
    """
    conn_data = monitor_active_connections(max_connections=500)
    connections = conn_data.get("connections", [])

    findings: List[Dict[str, Any]] = []

    outbound = [
        c for c in connections
        if str(c.get("state", "")).upper() in ("ESTABLISHED", "ESTAB", "CLOSE_WAIT")
        and _is_external(str(c.get("remote_addr", "")))
    ]

    # Count connections per external IP
    external_ip_counts: Dict[str, int] = {}
    for c in outbound:
        ip = str(c.get("remote_addr", ""))
        external_ip_counts[ip] = external_ip_counts.get(ip, 0) + 1

    # Flag IPs with many connections (C2 beaconing or flood)
    for ip, count in external_ip_counts.items():
        if count >= 20:
            findings.append({
                "signal_type": "suspicious_outbound",
                "severity": "high",
                "description": f"High connection count ({count}) to external IP {ip}",
                "indicators": {"remote_ip": ip, "connection_count": count},
            })

    # Flag connections to known-bad ports
    for c in outbound:
        remote_port = c.get("remote_port")
        if isinstance(remote_port, int) and remote_port in _SUSPICIOUS_OUTBOUND_PORTS:
            findings.append({
                "signal_type": "c2_communication",
                "severity": "high",
                "description": (
                    f"Outbound connection to suspicious port {remote_port} "
                    f"(remote: {c.get('remote_addr')})"
                ),
                "indicators": {
                    "remote_addr": c.get("remote_addr"),
                    "remote_port": remote_port,
                    "process": c.get("process"),
                    "pid": c.get("pid"),
                },
            })

    # Flag processes with high external connection counts
    process_external_counts: Dict[str, int] = {}
    for c in outbound:
        proc = str(c.get("process") or "unknown")
        process_external_counts[proc] = process_external_counts.get(proc, 0) + 1

    for proc, count in process_external_counts.items():
        if count >= 30 and proc != "unknown":
            findings.append({
                "signal_type": "unusual_connection",
                "severity": "medium",
                "description": (
                    f"Process '{proc}' has {count} external connections — "
                    "possible data exfiltration or abuse."
                ),
                "indicators": {"process": proc, "external_connection_count": count},
            })

    threat_score = score_network_threat({
        "findings": findings,
        "unique_external_ips": len(external_ip_counts),
    })

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "total_outbound": len(outbound),
        "unique_external_ips": len(external_ip_counts),
        "external_ip_distribution": dict(
            sorted(external_ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        ),
        "findings": findings,
        "threat_score": threat_score,
        "raw_connection_summary": conn_data.get("state_counts", {}),
    }


# ---------------------------------------------------------------------------
# TOOL 6 — Full network threat assessment (aggregator)
# ---------------------------------------------------------------------------

def assess_network_threats() -> Dict[str, Any]:
    """High-level network threat assessment aggregating active connections,
    outbound analysis, ARP table, DNS behaviour, and traffic volume.

    This is the primary tool the agent should call first. Other tools are
    available for targeted deep-dives.
    """
    all_findings: List[Dict[str, Any]] = []

    # 1. Outbound analysis (captures active connections internally)
    outbound = analyze_outbound_connections()
    all_findings.extend(outbound.get("findings", []))
    unique_external_ips = outbound.get("unique_external_ips", 0)
    total_outbound = outbound.get("total_outbound", 0)

    # 2. ARP spoofing
    arp = analyze_arp_table()
    all_findings.extend(arp.get("findings", []))

    # 3. DNS behaviour
    dns = analyze_dns_behavior()
    all_findings.extend(dns.get("findings", []))
    unknown_resolvers = dns.get("unknown_resolvers", [])

    # 4. Traffic volume
    traffic = analyze_traffic_volume()
    high_egress_ifaces = traffic.get("high_egress_interfaces", [])
    total_sent_mb = traffic.get("total_sent_mb", 0.0)

    if high_egress_ifaces:
        all_findings.append({
            "signal_type": "large_transfer",
            "severity": "medium",
            "description": (
                f"High cumulative egress on interfaces: "
                f"{[i.get('interface') for i in high_egress_ifaces]}"
            ),
            "indicators": {
                "interfaces": high_egress_ifaces,
                "total_sent_mb": total_sent_mb,
            },
        })

    # Unified score
    bytes_out_mbps_approx = total_sent_mb / 1024 if total_sent_mb else 0.0
    overall_score = score_network_threat({
        "findings": all_findings,
        "unique_external_ips": unique_external_ips,
        "bytes_out_mbps": bytes_out_mbps_approx,
    })

    sev_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = str(f.get("severity", "low")).lower()
        if sev in sev_summary:
            sev_summary[sev] += 1

    return {
        "assessed_at": datetime.now(UTC).isoformat(),
        "network_profile": {
            "total_outbound_connections": total_outbound,
            "unique_external_ips": unique_external_ips,
            "total_sent_mb": total_sent_mb,
            "arp_entries": arp.get("total_entries", 0),
            "dns_resolvers": dns.get("resolvers", []),
            "unknown_dns_resolvers": unknown_resolvers,
        },
        "findings": all_findings,
        "finding_summary": sev_summary,
        "threat_score": overall_score,
        "note": (
            "Network assessment is point-in-time. "
            "For egress baselining, correlate with historical traffic data."
        ),
    }


TOOLS = [
    assess_network_threats,
    analyze_outbound_connections,
    monitor_active_connections,
    analyze_arp_table,
    analyze_dns_behavior,
    analyze_traffic_volume,
]
