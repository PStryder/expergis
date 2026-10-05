"""Opt-in, per-user Windows runtime. Installation and credential entry are explicit.

No listeners, credentials, watchers or scheduled tasks are touched on import.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import getpass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import warnings

from expergis.auth0 import components, create_auth0_app, read_json
from expergis.protected_store import DPAPIProtector
from expergis.runtime_lock import RuntimeLock
from expergis.watch_scope import checked_local_path


def private_directory(directory):
    """Read owner/DACL only; refuse package redirection and never change permissions."""
    original = Path(directory)
    resolved = checked_local_path(str(original))
    if os.path.normcase(str(resolved)) != os.path.normcase(str(original)):
        raise ValueError("Run from an ordinary user terminal: private path is redirected")
    if os.name != "nt" or not resolved.is_dir():
        raise ValueError("An existing private Windows directory is required")
    script = r'''param([string]$Target)
$ErrorActionPreference='Stop'
$acl=[System.IO.Directory]::GetAccessControl($Target)
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$raw=[System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
$rules=@($acl.Access | ForEach-Object { @{sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; allow=($_.AccessControlType -eq 'Allow')} })
@{daclPresent=($null -ne $raw.DiscretionaryAcl); protected=$acl.AreAccessRulesProtected; owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; user=$user; rules=$rules} | ConvertTo-Json -Depth 4 -Compress
'''
    command = "& { " + script + " } '" + str(resolved).replace("'", "''") + "'"
    result = subprocess.run([r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise ValueError("Private ACL inspection failed")
    data = json.loads(result.stdout)
    allowed = {data["user"], "S-1-5-18", "S-1-5-32-544"}
    if (not data["daclPresent"] or not data["rules"] or not data["protected"] or data["owner"] != data["user"] or
            any(r["allow"] and r["sid"] not in allowed for r in data["rules"])):
        raise ValueError("Private owner-only directory ACL required")
    return resolved


def local_file(directory, name):
    target = directory / name
    if target.exists() or target.is_symlink():
        if checked_local_path(str(target)) != target or not target.is_file():
            raise ValueError("Unexpected state-file redirection")
        if target.stat().st_nlink != 1:
            raise ValueError("Hard-linked state file refused")
    return target


def load_config(directory):
    data = read_json(local_file(directory, "runtime.json"))
    if not isinstance(data, dict) or set(data) != {"expergis", "tunnel"}:
        raise ValueError("runtime.json requires expergis and tunnel objects")
    tunnel, config = data["tunnel"], data["expergis"]
    if (not isinstance(tunnel, dict) or set(tunnel) != {"id", "client_path", "sha256"}
            or not re.fullmatch(r"tunnel_[a-zA-Z0-9_-]{1,128}", tunnel.get("id", ""))
            or not re.fullmatch(r"[a-f0-9]{64}", tunnel.get("sha256", ""))):
        raise ValueError("Explicit tunnel ID, binary and verified checksum required")
    binary = checked_local_path(tunnel["client_path"])
    if not binary.is_file() or binary.stat().st_size > 200_000_000:
        raise ValueError("Invalid tunnel binary")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != tunnel["sha256"]:
        raise ValueError("Tunnel binary checksum mismatch")
    options = config.get("mcp_events", {})
    if (config.get("delivery_adapter") != "mcp_events" or config.get("watchers", [])
            or options.get("allowed_roots") is None or options.get("allowed_process_names") is None
            or type(options.get("allow_schedules")) is not bool):
        raise ValueError("Explicit monitoring scope and empty static watchers required")
    if (not isinstance(options["allowed_roots"], list) or len(options["allowed_roots"]) > 16
            or not isinstance(options["allowed_process_names"], list) or len(options["allowed_process_names"]) > 32):
        raise ValueError("Invalid monitoring scope")
    for root in options["allowed_roots"]:
        if not checked_local_path(root).is_dir():
            raise ValueError("Approved roots must be existing directories")
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
           for name in options["allowed_process_names"]):
        raise ValueError("Explicit executable names required")
    # Legacy Dispatcher still requires this field; event mode never dispatches to it.
    config["velle_endpoint"] = "http://127.0.0.1:1/disabled"
    # Fixed private state paths; never honor external database/policy overrides.
    config["mcp_events"]["database"] = str(local_file(directory, "events.db"))
    config["auth0"]["policy_file"] = str(local_file(directory, "policy.json"))
    components(config)  # Offline only. No credential or JWKS access.
    return config, tunnel


def write_status(directory, state, reason=None):
    data = {"state": state, "pid": os.getpid(), "updated_at": datetime.now(timezone.utc).isoformat()}
    if reason:
        data["reason"] = reason  # Call sites use fixed codes, never exception strings.
    temporary = local_file(directory, "status.tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    temporary.replace(local_file(directory, "status.json"))


def tunnel_configuration(config, tunnel, origin, health):
    return {"config_version": 1,
        "control_plane": {"base_url": "https://api.openai.com", "tunnel_id": tunnel["id"],
            "api_key": "env:CONTROL_PLANE_API_KEY", "max_inflight_requests": 2},
        "mcp": {"server_urls": [{"channel": "main", "url": origin + "/mcp"}],
            "oauth_trusted_origins": [origin, config["auth0"]["issuer"].rstrip("/")],
            "max_concurrent_requests": 2},
        "harpoon": {"allow_plaintext_http": True},
        "health": {"listen_addr": "127.0.0.1:0", "url_file": str(health)},
        "admin_ui": {"open_browser": False}, "cloudflared": {"managed": False},
        "log": {"level": "warn", "format": "json"}}


def tunnel_environment(key, directory):
    # No ambient tokens, proxies or other tool credentials inherited by the child.
    return {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows",
        "TEMP": str(directory), "TMP": str(directory), "HOME": str(directory),
        "USERPROFILE": str(directory), "APPDATA": str(directory), "LOCALAPPDATA": str(directory),
        "XDG_CONFIG_HOME": str(directory), "CONTROL_PLANE_API_KEY": key}


async def tunnel_ready(health):
    import aiohttp
    from urllib.parse import urlsplit
    try:
        if not health.exists() or health.stat().st_size > 2048:
            return False
        raw = health.read_text().strip()
        url = urlsplit(raw)
        if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
                or url.username or url.password or url.query or url.fragment or url.path not in ("", "/")):
            return False
        async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=1)) as session:
            async with session.get(raw.rstrip("/") + "/readyz", allow_redirects=False) as response:
                return response.status == 200
    except (OSError, ValueError, aiohttp.ClientError, asyncio.TimeoutError):
        return False


async def run(directory):
    import uvicorn
    from expergis.windows_process import KillJob, TunnelMutex
    config, tunnel = load_config(directory)
    local_file(directory, "supervisor.lock")
    local_file(directory, "events.db.lock")
    lock = RuntimeLock(directory / "supervisor")
    mutex = None
    child, job, task, server = None, None, None, None
    try:
        mutex = TunnelMutex(tunnel["id"])
        write_status(directory, "starting")
        stop = local_file(directory, "stop.request")
        stop.unlink(missing_ok=True)
        health = local_file(directory, "tunnel-health.txt")
        health.unlink(missing_ok=True)
        logging.disable(logging.CRITICAL)  # No tokens, payloads or raw server errors in persisted logs.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(16)
            origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
            config["auth0"]["tunnel_local_resource"] = origin + "/mcp"
            app = create_auth0_app(config)
            server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False,
                proxy_headers=False, lifespan="on", timeout_keep_alive=5, limit_concurrency=16))
            task = asyncio.create_task(server.serve(sockets=[sock]))
            for _ in range(300):
                if task.done():
                    raise RuntimeError("SERVER_START_FAILED")
                if server.started:
                    break
                await asyncio.sleep(.1)
            else:
                raise RuntimeError("SERVER_START_TIMEOUT")
            with local_file(directory, "tunnel-key.dpapi").open("rb") as stored:
                sealed = stored.read(16385)
            if len(sealed) > 16384:
                raise ValueError("Credential size limit")
            key = DPAPIProtector().open(sealed).decode("ascii")
            if not key or len(key) > 1024 or any(c.isspace() for c in key):
                raise ValueError("Invalid stored credential")
            path = local_file(directory, "tunnel-runtime.json")
            path.write_text(json.dumps(tunnel_configuration(config, tunnel, origin, health)), encoding="utf-8")
            job = KillJob()
            env = tunnel_environment(key, directory)
            key = None
            try:
                child = subprocess.Popen([tunnel["client_path"], "run", "--config", str(path)],
                    env=env, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            finally:
                env.clear()
            job.attach(child)
            ticks = 0
            while not stop.exists() and not task.done():
                if child.poll() is not None:
                    raise RuntimeError("TUNNEL_EXITED")
                ready = await tunnel_ready(health)
                from expergis import server as runtime
                broken = any(entry.task and entry.task.done() for entry in runtime._watchers.values())
                if ticks % 15 == 0:
                    write_status(directory, "degraded" if broken or not ready else "ready",
                        "WATCHER_STOPPED" if broken else (None if ready else "TUNNEL_NOT_READY"))
                ticks += 1
                await asyncio.sleep(1)
            if task.done() and not stop.exists() and not server.should_exit:
                raise RuntimeError("SERVER_EXITED")
    except BaseException:
        write_status(directory, "failed", "RUNTIME_FAILED")
        raise
    finally:
        if server:
            server.should_exit = True
        if task:
            try:
                await asyncio.wait_for(task, timeout=10)
            except BaseException:
                task.cancel()
        if child and child.poll() is None:
            child.terminate()
            try:
                await asyncio.to_thread(child.wait, 5)
            except subprocess.TimeoutExpired:
                child.kill()
                await asyncio.to_thread(child.wait, 5)
        if job:
            job.close()
        if mutex:
            mutex.close()
        lock.close()
    write_status(directory, "stopped")


def main():
    parser = argparse.ArgumentParser(description="Explicit per-user Expergis runtime operations")
    parser.add_argument("action", choices=("preflight", "store-key", "run", "status", "stop"))
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    directory = None
    try:
        directory = private_directory(args.directory)
        if args.action == "preflight":
            config, _ = load_config(directory)
            print("Offline config/ACL/checksum valid. No network, credentials or watchers started.")
            print("Approved roots:", len(config["mcp_events"]["allowed_roots"]),
                  "process names:", len(config["mcp_events"]["allowed_process_names"]))
        elif args.action == "store-key":
            if not sys.stdin.isatty():
                raise ValueError("Interactive local credential entry required")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Dedicated Tunnels Read + Use key (hidden): ")
            if not key or len(key) > 1024 or not key.isascii() or any(c.isspace() for c in key):
                raise ValueError("Invalid credential input")
            sealed = DPAPIProtector().seal(key.encode("ascii"))
            key = None
            temporary = local_file(directory, "key.tmp")
            temporary.write_bytes(sealed)
            temporary.replace(local_file(directory, "tunnel-key.dpapi"))
            print("Saved user-bound DPAPI credential. Restart required after rotation.")
        elif args.action == "status":
            data = read_json(local_file(directory, "status.json"))
            print(json.dumps({k: data.get(k) for k in ("state", "pid", "updated_at", "reason")}))
            print("Status is a timestamped snapshot, not proof of current process or dot receipt.")
        elif args.action == "stop":
            local_file(directory, "stop.request").touch()
            print("Stop requested. Disable the logon task separately to prevent a future launch.")
        else:
            asyncio.run(run(directory))
    except KeyboardInterrupt:
        print("Runtime interrupted; children stopped.")
        return 0
    except Exception:
        if args.action == "run" and directory is not None:
            try:
                write_status(directory, "failed", "STARTUP_OR_RUNTIME_FAILED")
            except Exception:
                pass
        print("Operation failed. Check private ACL, offline config, runtime status and approved environment. No raw values logged.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
