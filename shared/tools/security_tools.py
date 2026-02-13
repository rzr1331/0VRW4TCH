from __future__ import annotations

from datetime import UTC, datetime
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SUSPICIOUS_PATTERNS = [
    "bash -i",
    "nc -e",
    "curl | sh",
    "wget http",
    "mimikatz",
    "sqlmap",
]
SENSITIVE_PORTS = {22, 2375, 3306, 5432, 6379, 6443, 9200, 27017}


def _run_command(
    command: List[str], timeout_seconds: int = 12
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _looks_like_host_target(target: str) -> bool:
    return bool(
        re.match(r"^(([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+)$", target)
        or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
    )


def _severity_bucket(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        if severity in by_severity:
            by_severity[severity] += 1
    return by_severity


def _append_finding(
    findings: List[Dict[str, Any]],
    *,
    finding_id: str,
    severity: str,
    title: str,
    description: str,
    source: str,
    evidence: List[str],
    recommendation: str,
) -> None:
    findings.append(
        {
            "id": finding_id,
            "severity": severity,
            "title": title,
            "description": description,
            "source": source,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def _scan_with_falco(tool_results: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str | None:
    if shutil.which("falco") is None:
        return "falco"

    version = _run_command(["falco", "--version"], timeout_seconds=3)
    running = _run_command(["pgrep", "-x", "falco"], timeout_seconds=2)
    is_running = bool(running and running.returncode == 0 and running.stdout.strip())

    tool_results.append(
        {
            "tool": "falco",
            "status": "ok" if version and version.returncode == 0 else "error",
            "available": True,
            "running": is_running,
            "details": (version.stdout or version.stderr or "").strip()[:240]
            if version
            else "Unable to execute falco --version.",
        }
    )

    if not is_running:
        _append_finding(
            findings,
            finding_id="falco-not-running",
            severity="medium",
            title="Falco installed but not running",
            description="Falco binary was detected, but no running Falco process was found.",
            source="falco",
            evidence=["pgrep -x falco returned no active process"],
            recommendation="Start and supervise Falco to enable runtime threat detection.",
        )
    return None


def _scan_with_osquery(tool_results: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str | None:
    if shutil.which("osqueryi") is None:
        return "osqueryi"

    result = _run_command(
        [
            "osqueryi",
            "--json",
            "select pid, name, cmdline from processes limit 120;",
        ],
        timeout_seconds=12,
    )
    if result is None:
        tool_results.append(
            {
                "tool": "osqueryi",
                "status": "error",
                "available": True,
                "details": "Failed to run osqueryi process query.",
            }
        )
        return None

    if result.returncode != 0:
        tool_results.append(
            {
                "tool": "osqueryi",
                "status": "error",
                "available": True,
                "details": (result.stderr or result.stdout).strip()[:240],
            }
        )
        return None

    rows: List[Dict[str, Any]] = []
    try:
        decoded = json.loads(result.stdout or "[]")
        if isinstance(decoded, list):
            rows = [row for row in decoded if isinstance(row, dict)]
    except json.JSONDecodeError:
        pass

    suspicious_count = 0
    for row in rows:
        cmdline = str(row.get("cmdline", "")).lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern not in cmdline:
                continue
            suspicious_count += 1
            _append_finding(
                findings,
                finding_id=f"osq-proc-{row.get('pid', 'unknown')}",
                severity="high",
                title="Suspicious command pattern discovered",
                description=f"Process command line matched suspicious pattern: {pattern}",
                source="osqueryi",
                evidence=[
                    f"pid={row.get('pid', 'unknown')}",
                    f"name={row.get('name', 'unknown')}",
                    f"cmdline={str(row.get('cmdline', ''))[:180]}",
                ],
                recommendation="Validate process legitimacy and isolate host if unauthorized.",
            )
            break

    tool_results.append(
        {
            "tool": "osqueryi",
            "status": "ok",
            "available": True,
            "rows_scanned": len(rows),
            "suspicious_matches": suspicious_count,
        }
    )
    return None


def _scan_with_trivy(
    target: str, tool_results: List[Dict[str, Any]], findings: List[Dict[str, Any]]
) -> str | None:
    if shutil.which("trivy") is None:
        return "trivy"

    normalized_target = target.strip() or "."
    if os.path.exists(normalized_target):
        command = ["trivy", "fs", "--quiet", "--format", "json", normalized_target]
        scan_mode = "filesystem"
    elif ":" in normalized_target or "/" in normalized_target:
        command = ["trivy", "image", "--quiet", "--format", "json", normalized_target]
        scan_mode = "image"
    else:
        tool_results.append(
            {
                "tool": "trivy",
                "status": "skipped",
                "available": True,
                "details": "Target is not a local path or image reference.",
            }
        )
        return None

    result = _run_command(command, timeout_seconds=90)
    if result is None:
        tool_results.append(
            {
                "tool": "trivy",
                "status": "error",
                "available": True,
                "mode": scan_mode,
                "details": "Trivy command execution failed.",
            }
        )
        return None

    if result.returncode not in (0, 1):
        tool_results.append(
            {
                "tool": "trivy",
                "status": "error",
                "available": True,
                "mode": scan_mode,
                "details": (result.stderr or result.stdout).strip()[:240],
            }
        )
        return None

    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        tool_results.append(
            {
                "tool": "trivy",
                "status": "error",
                "available": True,
                "mode": scan_mode,
                "details": "Trivy output was not valid JSON.",
            }
        )
        return None

    results = payload.get("Results", []) if isinstance(payload, dict) else []
    vuln_count = 0
    for record in results:
        if not isinstance(record, dict):
            continue
        target_name = str(record.get("Target", normalized_target))
        vulnerabilities = record.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities[:120]:
            if not isinstance(vulnerability, dict):
                continue
            vuln_count += 1
            raw_severity = str(vulnerability.get("Severity", "LOW")).lower()
            severity = raw_severity if raw_severity in SEVERITY_ORDER else "low"
            _append_finding(
                findings,
                finding_id=f"trivy-{vulnerability.get('VulnerabilityID', 'unknown')}",
                severity=severity,
                title=f"Vulnerability {vulnerability.get('VulnerabilityID', 'unknown')}",
                description=str(vulnerability.get("Title") or vulnerability.get("Description") or "No description."),
                source="trivy",
                evidence=[
                    f"target={target_name}",
                    f"package={vulnerability.get('PkgName', 'unknown')}",
                    f"installed={vulnerability.get('InstalledVersion', 'unknown')}",
                    f"fixed={vulnerability.get('FixedVersion', 'unknown')}",
                ],
                recommendation="Patch to a fixed version and review exploitability in your environment.",
            )

    tool_results.append(
        {
            "tool": "trivy",
            "status": "ok",
            "available": True,
            "mode": scan_mode,
            "vulnerabilities_found": vuln_count,
        }
    )
    return None


def _scan_with_nmap(
    target: str, tool_results: List[Dict[str, Any]], findings: List[Dict[str, Any]]
) -> str | None:
    if shutil.which("nmap") is None:
        return "nmap"

    normalized_target = target.strip()
    if not normalized_target or not _looks_like_host_target(normalized_target):
        tool_results.append(
            {
                "tool": "nmap",
                "status": "skipped",
                "available": True,
                "details": "Target is not a host/IP value suitable for nmap.",
            }
        )
        return None

    result = _run_command(
        [
            "nmap",
            "-Pn",
            "--top-ports",
            "200",
            "--open",
            "-oX",
            "-",
            normalized_target,
        ],
        timeout_seconds=45,
    )
    if result is None or result.returncode not in (0, 1):
        tool_results.append(
            {
                "tool": "nmap",
                "status": "error",
                "available": True,
                "details": (result.stderr if result else "nmap execution failed.")[:240] if result else "nmap execution failed.",
            }
        )
        return None

    open_ports: List[int] = []
    try:
        root = ET.fromstring(result.stdout or "")
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            port_id = port.attrib.get("portid")
            if port_id and port_id.isdigit():
                open_ports.append(int(port_id))
    except ET.ParseError:
        tool_results.append(
            {
                "tool": "nmap",
                "status": "error",
                "available": True,
                "details": "Unable to parse nmap XML output.",
            }
        )
        return None

    sensitive_exposed = sorted({port for port in open_ports if port in SENSITIVE_PORTS})
    for port in sensitive_exposed:
        _append_finding(
            findings,
            finding_id=f"nmap-open-port-{port}",
            severity="high",
            title=f"Sensitive port {port} exposed",
            description=f"nmap discovered publicly reachable sensitive port {port} on target {normalized_target}.",
            source="nmap",
            evidence=[f"target={normalized_target}", f"port={port}"],
            recommendation="Restrict network exposure using firewall rules and access controls.",
        )

    tool_results.append(
        {
            "tool": "nmap",
            "status": "ok",
            "available": True,
            "open_ports_found": len(open_ports),
            "sensitive_ports_found": len(sensitive_exposed),
        }
    )
    return None


def run_security_scan(target: str) -> Dict[str, Any]:
    """
    Best-effort security scan across optional local tools.
    Missing tools never fail the scan; results include what was available.
    """
    findings: List[Dict[str, Any]] = []
    tool_results: List[Dict[str, Any]] = []
    missing_tools: List[str] = []
    notes: List[str] = []
    normalized_target = target.strip() or "."

    for scanner in (
        lambda: _scan_with_falco(tool_results, findings),
        lambda: _scan_with_osquery(tool_results, findings),
        lambda: _scan_with_trivy(normalized_target, tool_results, findings),
        lambda: _scan_with_nmap(normalized_target, tool_results, findings),
    ):
        try:
            missing = scanner()
        except Exception as exc:  # Defensive: scanners should not break end-to-end execution.
            notes.append(f"scanner execution error: {exc}")
            continue
        if missing:
            missing_tools.append(missing)

    findings.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "low")), 1), reverse=True)
    by_severity = _severity_bucket(findings)
    if missing_tools:
        notes.append(
            "Some optional scanners are not installed. Results are partial and based on available tooling."
        )

    return {
        "target": normalized_target,
        "scanned_at": datetime.now(UTC).isoformat(),
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "tools_executed": len(tool_results),
            "tools_missing": len(missing_tools),
        },
        "tool_results": tool_results,
        "missing_tools": sorted(set(missing_tools)),
        "notes": notes,
    }
