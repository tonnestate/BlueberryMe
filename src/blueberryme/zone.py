from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


class ProbeStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass(frozen=True)
class ZoneProbe:
    name: str
    status: ProbeStatus
    detail: str


@dataclass(frozen=True)
class ZoneProfile:
    workspace: str = "."
    gateway_hosts: tuple[str, ...] = ()
    llm_hosts: tuple[str, ...] = ()
    source_hosts: tuple[str, ...] = ()
    target_hosts: tuple[str, ...] = ()
    keep_env: tuple[str, ...] = ()
    srt_binary: str = "srt"


_SENSITIVE_ENV = re.compile(r"(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)$", re.IGNORECASE)
_EXACT_SENSITIVE_ENV = {
    "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
}
_BASE_ENV = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR", "TEMP", "TMP"}
_SENSITIVE_PATHS = (
    "~/.ssh", "~/.aws", "~/.config/gh", "~/.docker/config.json",
    "~/.kube/config", "/var/run/docker.sock",
)


def _host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname or value.split(":", 1)[0]


def _host_port(value: str, default_port: int = 443) -> tuple[str, int]:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split(":", 1)[0]
    return host, parsed.port or default_port


def sanitized_environment(keep: Iterable[str] = ()) -> dict[str, str]:
    allowed = set(_BASE_ENV) | set(keep)
    allowed.update(name for name in os.environ if name.startswith("LC_"))
    return {name: value for name, value in os.environ.items() if name in allowed}


def build_srt_settings(profile: ZoneProfile) -> dict:
    workspace = str(Path(profile.workspace).resolve())
    allowed_domains = sorted({h for h in (_host(x) for x in (*profile.gateway_hosts, *profile.llm_hosts)) if h})
    return {
        "filesystem": {
            "denyRead": ["~"],
            "allowRead": [workspace],
            "allowWrite": [workspace],
            "denyWrite": list(_SENSITIVE_PATHS),
        },
        "network": {"allowedDomains": allowed_domains, "deniedDomains": []},
    }


def run_agent(profile: ZoneProfile, command: list[str]) -> int:
    if not command:
        raise ValueError("No agent command supplied")
    binary = shutil.which(profile.srt_binary)
    if not binary:
        raise RuntimeError("Anthropic sandbox-runtime 'srt' was not found. Install it or use another BBM-conformant execution boundary.")
    fd, path = tempfile.mkstemp(prefix="bbm-srt-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(build_srt_settings(profile), handle, separators=(",", ":"))
        completed = subprocess.run([binary, "--settings", path, *command], env=sanitized_environment(profile.keep_env), check=False)
        return int(completed.returncode)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _credential_env_probe() -> ZoneProbe:
    leaked = [name for name in os.environ if name in _EXACT_SENSITIVE_ENV or _SENSITIVE_ENV.search(name)]
    if leaked:
        return ZoneProbe("credential_environment", ProbeStatus.FAIL, f"{len(leaked)} credential-like environment variable name(s) visible")
    return ZoneProbe("credential_environment", ProbeStatus.PASS, "no credential-like environment names visible")


def _path_probe(path: str) -> ZoneProbe:
    expanded = Path(path).expanduser()
    try:
        if expanded.is_dir():
            next(expanded.iterdir(), None)
        else:
            with expanded.open("rb") as handle:
                handle.read(1)
    except (FileNotFoundError, PermissionError, OSError):
        return ZoneProbe(f"path:{path}", ProbeStatus.PASS, "not readable from agent zone")
    return ZoneProbe(f"path:{path}", ProbeStatus.FAIL, "sensitive host path is readable")


def _blocked_host_probe(label: str, value: str, timeout: float) -> ZoneProbe:
    host, port = _host_port(value)
    if not host:
        return ZoneProbe(label, ProbeStatus.SKIP, "not configured")
    if _connect(host, port, timeout):
        return ZoneProbe(label, ProbeStatus.FAIL, f"direct route reachable at {host}:{port}")
    return ZoneProbe(label, ProbeStatus.PASS, f"direct route blocked at {host}:{port}")


def _allowed_host_probe(label: str, value: str, timeout: float) -> ZoneProbe:
    host, port = _host_port(value)
    if not host:
        return ZoneProbe(label, ProbeStatus.SKIP, "not configured")
    if _connect(host, port, timeout):
        return ZoneProbe(label, ProbeStatus.PASS, f"approved route reachable at {host}:{port}")
    return ZoneProbe(label, ProbeStatus.FAIL, f"approved route not reachable at {host}:{port}")


def zone_check(profile: ZoneProfile, *, timeout: float = 0.5) -> list[ZoneProbe]:
    probes: list[ZoneProbe] = [_credential_env_probe()]
    probes.extend(_path_probe(path) for path in _SENSITIVE_PATHS)
    probes.extend(_blocked_host_probe(f"source_route:{i}", value, timeout) for i, value in enumerate(profile.source_hosts))
    probes.extend(_blocked_host_probe(f"target_route:{i}", value, timeout) for i, value in enumerate(profile.target_hosts))
    probes.append(_blocked_host_probe("cloud_metadata", "169.254.169.254:80", timeout))
    probes.append(_blocked_host_probe("arbitrary_internet", "example.com:443", timeout))
    probes.extend(_allowed_host_probe(f"gateway_route:{i}", value, timeout) for i, value in enumerate(profile.gateway_hosts))
    probes.extend(_allowed_host_probe(f"llm_route:{i}", value, timeout) for i, value in enumerate(profile.llm_hosts))
    try:
        socket.getaddrinfo("bbm-zone-check.invalid", 443)
        probes.append(ZoneProbe("arbitrary_dns", ProbeStatus.WARN, "unexpected DNS resolution succeeded"))
    except OSError:
        probes.append(ZoneProbe("arbitrary_dns", ProbeStatus.WARN, "fixed sentinel did not resolve; DNS exfiltration still requires sandbox/network-policy verification"))
    if not profile.gateway_hosts:
        probes.append(ZoneProbe("gateway_configuration", ProbeStatus.WARN, "no gateway host configured for positive reachability test"))
    return probes


def zone_check_summary(probes: Iterable[ZoneProbe]) -> dict:
    items = list(probes)
    counts = {status.value: sum(1 for item in items if item.status is status) for status in ProbeStatus}
    return {"pass": counts[ProbeStatus.FAIL.value] == 0, "counts": counts, "probes": [asdict(item) for item in items]}
