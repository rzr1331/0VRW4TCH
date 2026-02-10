from __future__ import annotations

from datetime import UTC, datetime
import platform
import re
import shutil
import subprocess
from typing import Any, Dict, List


def _run_command(command: List[str], timeout_seconds: int = 3) -> subprocess.CompletedProcess[str] | None:
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


def _discover_processes(limit: int = 200) -> List[Dict[str, Any]]:
    if shutil.which("ps") is None:
        return []
    result = _run_command(["ps", "-axo", "pid=,comm=,args="], timeout_seconds=5)
    if result is None or result.returncode != 0:
        return []

    processes: List[Dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        pid_raw = parts[0]
        if not pid_raw.isdigit():
            continue
        processes.append(
            {
                "pid": int(pid_raw),
                "command": parts[1],
                "args": parts[2] if len(parts) > 2 else parts[1],
            }
        )
        if len(processes) >= limit:
            break
    return processes


def _discover_docker_containers(limit: int = 100) -> List[Dict[str, Any]]:
    if shutil.which("docker") is None:
        return []
    result = _run_command(
        ["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}"]
    )
    if result is None or result.returncode != 0:
        return []

    containers: List[Dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        containers.append(
            {"id": parts[0], "name": parts[1], "image": parts[2], "status": parts[3]}
        )
        if len(containers) >= limit:
            break
    return containers


def _systemctl_main_pid(unit_name: str) -> int | None:
    result = _run_command(
        ["systemctl", "show", unit_name, "--property", "MainPID", "--value"], timeout_seconds=2
    )
    if result is None or result.returncode != 0:
        return None
    value = result.stdout.strip()
    if value.isdigit() and value != "0":
        return int(value)
    return None


def _discover_systemd_services(limit: int = 120) -> Dict[str, Any]:
    if shutil.which("systemctl") is None:
        return {"available": False, "running_services": []}

    result = _run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ],
        timeout_seconds=4,
    )
    if result is None or result.returncode != 0:
        return {"available": True, "running_services": [], "error": "systemctl query failed"}

    services: List[Dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 1:
            continue
        unit_name = parts[0]
        description = parts[4] if len(parts) >= 5 else ""
        services.append(
            {
                "unit": unit_name,
                "description": description,
                "main_pid": _systemctl_main_pid(unit_name),
            }
        )
        if len(services) >= limit:
            break

    return {"available": True, "running_services": services}


def _discover_open_ports(limit: int = 200) -> Dict[str, Any]:
    ports: List[Dict[str, Any]] = []

    if shutil.which("ss") is not None:
        result = _run_command(["ss", "-lntupH"], timeout_seconds=4)
        if result is not None and result.returncode == 0:
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                protocol = parts[0]
                local = parts[4]
                port_match = re.search(r":(\d+)$", local)
                pid_match = re.search(r"pid=(\d+)", line)
                process_match = re.search(r'users:\\(\\(\"([^"]+)"', line)
                if port_match is None:
                    continue
                ports.append(
                    {
                        "protocol": protocol,
                        "local_address": local,
                        "port": int(port_match.group(1)),
                        "pid": int(pid_match.group(1)) if pid_match else None,
                        "process": process_match.group(1) if process_match else None,
                    }
                )
                if len(ports) >= limit:
                    break
            return {"available": True, "source": "ss", "listeners": ports}

    if shutil.which("lsof") is not None:
        result = _run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout_seconds=5)
        if result is not None and result.returncode == 0:
            for idx, raw_line in enumerate(result.stdout.splitlines()):
                if idx == 0:
                    continue
                line = raw_line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 9:
                    continue
                command = parts[0]
                pid_raw = parts[1]
                name_field = parts[-1]
                port_match = re.search(r":(\d+)", name_field)
                if not pid_raw.isdigit() or port_match is None:
                    continue
                ports.append(
                    {
                        "protocol": "tcp",
                        "local_address": name_field,
                        "port": int(port_match.group(1)),
                        "pid": int(pid_raw),
                        "process": command,
                    }
                )
                if len(ports) >= limit:
                    break
            return {"available": True, "source": "lsof", "listeners": ports}

    return {"available": False, "listeners": []}


def _is_public_listener(local_address: str) -> bool:
    normalized = (local_address or "").strip().lower()
    return (
        normalized.startswith("0.0.0.0:")
        or normalized.startswith("*:")
        or normalized.startswith("[::]:")
        or normalized.startswith(":::")
    )


def _map_processes_to_services(
    processes: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    process_by_pid = {proc["pid"]: proc for proc in processes}
    mappings: List[Dict[str, Any]] = []

    for svc in services:
        main_pid = svc.get("main_pid")
        if isinstance(main_pid, int) and main_pid in process_by_pid:
            proc = process_by_pid[main_pid]
            mappings.append(
                {
                    "service": svc["unit"],
                    "pid": main_pid,
                    "command": proc["command"],
                    "args": proc["args"],
                }
            )

    return mappings


def discover_runtime_assets(max_processes: int = 200) -> Dict[str, Any]:
    processes = _discover_processes(limit=max(10, min(max_processes, 2000)))
    containers = _discover_docker_containers()
    systemd_info = _discover_systemd_services()
    open_ports_info = _discover_open_ports()

    python_processes = [
        proc
        for proc in processes
        if (
            "python" in proc["command"].lower()
            or ".py" in proc["args"].lower()
            or "gunicorn" in proc["args"].lower()
            or "uvicorn" in proc["args"].lower()
            or "celery" in proc["args"].lower()
        )
    ]

    running_services = systemd_info.get("running_services", [])
    service_process_map = _map_processes_to_services(processes, running_services)
    listeners = open_ports_info.get("listeners", [])
    public_listeners = [
        listener
        for listener in listeners
        if _is_public_listener(str(listener.get("local_address", "")))
    ]

    runtime_profile = "dockerized" if containers else "host-process"
    if containers and (python_processes or running_services):
        runtime_profile = "hybrid"

    monitoring_targets: List[Dict[str, Any]] = [
        {"type": "host", "name": "cpu_usage_percent"},
        {"type": "host", "name": "memory_usage_percent"},
        {"type": "host", "name": "disk_usage_percent"},
        {"type": "host", "name": "network_io_mbps"},
    ]

    for proc in python_processes[:50]:
        monitoring_targets.append(
            {
                "type": "process",
                "pid": proc["pid"],
                "name": proc["command"],
                "metric_set": ["cpu", "memory", "restarts", "latency", "errors"],
            }
        )

    for svc in running_services[:50]:
        monitoring_targets.append(
            {
                "type": "service",
                "name": svc["unit"],
                "pid": svc.get("main_pid"),
                "metric_set": ["uptime", "restarts", "cpu", "memory", "errors"],
            }
        )

    for listener in listeners[:50]:
        monitoring_targets.append(
            {
                "type": "port",
                "name": f'{listener.get("protocol", "tcp")}:{listener["port"]}',
                "pid": listener.get("pid"),
                "process": listener.get("process"),
                "metric_set": ["connection_rate", "errors", "latency"],
            }
        )

    for container in containers[:50]:
        monitoring_targets.append(
            {
                "type": "container",
                "name": container["name"],
                "image": container["image"],
                "metric_set": ["cpu", "memory", "restarts", "network", "errors"],
            }
        )

    recommended_collectors = ["node_exporter", "application_logs"]
    if running_services:
        recommended_collectors.append("systemd_exporter")
    if python_processes:
        recommended_collectors.append("process_exporter")
    if containers:
        recommended_collectors.extend(["cadvisor_or_docker_stats", "container_logs"])

    return {
        "discovered_at": datetime.now(UTC).isoformat(),
        "host": {"platform": platform.system(), "platform_release": platform.release()},
        "runtime_profile": runtime_profile,
        "docker": {
            "available": shutil.which("docker") is not None,
            "running_containers": containers,
            "count": len(containers),
        },
        "systemd": {
            "available": systemd_info.get("available", False),
            "running_services": running_services[:80],
            "count": len(running_services),
            "error": systemd_info.get("error"),
        },
        "open_ports": {
            "available": open_ports_info.get("available", False),
            "source": open_ports_info.get("source"),
            "listeners": listeners[:100],
            "count": len(listeners),
            "public_listeners": public_listeners[:100],
            "public_count": len(public_listeners),
        },
        "processes": {
            "sample_count": len(processes),
            "sample": processes[:200],
            "python_service_count": len(python_processes),
            "python_services": python_processes[:80],
        },
        "service_process_map": service_process_map[:100],
        "monitoring_targets": monitoring_targets,
        "recommended_collectors": sorted(set(recommended_collectors)),
        "note": "Runtime discovery is best-effort per host capabilities. Integrate CMDB/inventory for full coverage.",
    }
