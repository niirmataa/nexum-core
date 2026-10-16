#!/usr/bin/python3 -I
"""OPS: root-installed broker for two existing, constrained Nexum containers."""
import json
import os
import re
import stat
import subprocess
import sys
import tomllib

WORKSPACE = "/home/footfalcon/Dokumenty/ChatGPT/nexum-core 2"
USER_UID, USER_GID = 1000, 1000
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
DOCKER_CONFIG = "/etc/docker/daemon.json"
# Owner-approved exception after moving to the new Micron system filesystem.
# This does not permit arbitrary directories on / or a different root disk.
APPROVED_ROOT_BASE = "/var/lib/nexum-docker"
APPROVED_ROOT_UUID = "09929a1b-d005-4a5a-9fe3-29ab45851965"
READ_TIMEOUT = 60
MAX_DAEMON_CONFIG_BYTES = 64 * 1024
HOST_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C.UTF-8"}
CONTAINERS = {"dev": "nexum-alpine-dev", "stagenet": "nexum-alpine-stagenet"}
# Moby v28.5.1 oci/defaults.go: accept supersets, preserving host-specific masks.
# https://github.com/moby/moby/blob/v28.5.1/oci/defaults.go
MASKED_PATHS = {
    "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
    "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap",
}
READONLY_PATHS = {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
DEV_ENV = {
    "PATH": "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/cache/home", "CARGO_HOME": "/cache/cargo",
    "CARGO_TARGET_DIR": "/cache/target", "XDG_CACHE_HOME": "/cache/xdg",
    "TMPDIR": "/cache/tmp", "RUSTUP_HOME": "/usr/local/rustup",
    "RUSTUP_TOOLCHAIN": "1.94.0", "CARGO_BUILD_JOBS": "1",
    "MAKEFLAGS": "-j1", "CMAKE_BUILD_PARALLEL_LEVEL": "1",
    "CFLAGS": "-I/usr/local/include", "RUSTFLAGS": "-L native=/usr/local/lib",
    "LD_LIBRARY_PATH": "/usr/local/lib",
}
VERSIONS = """
set -e
rustc --version
cargo --version
for tool in rustfmt cargo-clippy cmake; do
    if command -v "$tool" >/dev/null 2>&1; then "$tool" --version; fi
done
if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --modversion libsodium 2>/dev/null || :
    pkg-config --modversion liboqs 2>/dev/null || :
fi
if command -v monerod >/dev/null 2>&1; then monerod --version; fi
if command -v monero-wallet-rpc >/dev/null 2>&1; then monero-wallet-rpc --version; fi
if command -v tor >/dev/null 2>&1; then tor --version; fi
"""
USAGE = """Usage: nexum-docker-agent status
       nexum-docker-agent storage-check
       nexum-docker-agent services-start
       nexum-docker-agent logs {dev,stagenet}
       nexum-docker-agent {start,stop,restart} {dev,stagenet}
       nexum-docker-agent dev cargo ARGS...
       nexum-docker-agent dev versions
Only existing containers are supported. No create/remove, host shell or root exec.
"""


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def run(argv, *, capture=True, timeout=READ_TIMEOUT, check=True):
    result = subprocess.run(argv, env=HOST_ENV, cwd="/", text=True,
                            capture_output=capture, timeout=timeout)
    if check and result.returncode:
        detail = (result.stderr or "").strip()[:2000]
        raise Refused(f"Command failed ({result.returncode}): {detail}")
    return result


def docker(*args, **kwargs):
    return run(DOCKER + list(args), **kwargs)


def docker_root_from_config(path=DOCKER_CONFIG):
    # Read only a root-controlled regular file, without following its symlink.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as config_file:
        metadata = os.fstat(config_file.fileno())
        require(stat.S_ISREG(metadata.st_mode), "Docker config must be a regular file.")
        require(metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
                "Docker config must be root-owned and not group/other-writable.")
        require(metadata.st_size <= MAX_DAEMON_CONFIG_BYTES,
                "Docker config exceeds the size limit.")
        body = config_file.read(MAX_DAEMON_CONFIG_BYTES + 1)
    require(len(body) <= MAX_DAEMON_CONFIG_BYTES, "Docker config exceeds the size limit.")
    config = json.loads(body)
    require(isinstance(config, dict), "Docker config must be a JSON object.")
    root = config.get("data-root", "")
    require(isinstance(root, str) and os.path.isabs(root)
            and os.path.realpath(root) == root and os.path.isdir(root),
            "Docker data-root must be an absolute canonical existing directory.")
    return root


def validate_approved_root_storage(docker_root, containerd_root):
    require(docker_root == APPROVED_ROOT_BASE + "/docker"
            and containerd_root == APPROVED_ROOT_BASE + "/containerd",
            "Storage on / is allowed only at the owner-approved Micron paths.")
    for path in ("/var", "/var/lib", APPROVED_ROOT_BASE, docker_root, containerd_root):
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise Refused(f"Approved storage directory is unavailable: {path}") from error
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0 and os.path.realpath(path) == path,
                f"Approved storage must use protected root-owned directories: {path}")
    filesystem = run(["/usr/bin/findmnt", "--noheadings", "--raw", "--output",
                      "UUID,FSTYPE", "--target", APPROVED_ROOT_BASE]).stdout.split()
    require(filesystem == [APPROVED_ROOT_UUID, "ext4"],
            "The approved Micron filesystem UUID/type does not match.")


def check_storage():
    root = docker_root_from_config()
    docker_fs = os.stat(root).st_dev
    # config dump resolves imports, unlike reading only the initial TOML file.
    config = run(["/usr/bin/containerd", "--config", "/etc/containerd/config.toml",
                  "config", "dump"]).stdout
    containerd_root = tomllib.loads(config).get("root", "")
    require(os.path.isabs(containerd_root), "Cannot verify effective containerd root.")
    require(os.stat(containerd_root).st_dev == docker_fs,
            "containerd and Docker must use the same data filesystem.")
    if docker_fs == os.stat("/").st_dev:
        validate_approved_root_storage(root, containerd_root)
    return docker_fs


def services_start():
    run(["/usr/bin/systemctl", "start", "containerd.service", "docker.service"])
    run(["/usr/bin/systemctl", "is-active", "containerd.service", "docker.service"])
    print(json.dumps({"action": "services-start", "services": ["containerd.service", "docker.service"],
                      "active": True}))
    return 0


def check_volume(name, source, docker_fs):
    data = json.loads(docker("volume", "inspect", name).stdout)
    require(isinstance(data, list) and len(data) == 1, "Unexpected volume inspect response.")
    volume = data[0]
    require(volume.get("Name") == name and volume.get("Driver") == "local"
            and volume.get("Scope") == "local", "Unexpected volume identity, driver or scope.")
    require(volume.get("Options") in (None, {}), "Volume driver options are forbidden.")
    mountpoint = volume.get("Mountpoint", "")
    require(os.path.isabs(mountpoint) and os.path.realpath(mountpoint) == mountpoint
            and source == mountpoint, "Volume source does not match its canonical mountpoint.")
    expected_mountpoint = os.path.join(docker_root_from_config(), "volumes", name, "_data")
    require(mountpoint == expected_mountpoint,
            "Volume mountpoint must be inside the configured Docker data-root.")
    require(os.path.isdir(mountpoint) and os.stat(mountpoint).st_dev == docker_fs,
            "Volume mountpoint must be on the verified Docker data filesystem.")


def check_mounts(kind, mounts, docker_fs):
    expected = ({
        "/work/nexum-core": ("bind", WORKSPACE, True),
        "/work/privAI": ("bind", WORKSPACE + "/_incoming/privAI", False),
        "/cache": ("volume", "nexum-alpine-dev-cache", True),
    } if kind == "dev" else {
        "/state": ("volume", "nexum-alpine-stagenet-data", True),
        "/opt/alpine-stagenet.sh": ("bind", WORKSPACE + "/tools/alpine-stagenet.sh", False),
    })
    seen = set()
    for mount in mounts:
        dest = mount.get("Destination")
        require(dest not in seen, "Duplicate mount destination.")
        seen.add(dest)
        if dest == "/tmp" and mount.get("Type") == "tmpfs":
            continue
        require(dest in expected, f"Unexpected mount destination: {dest}")
        mount_type, source, writable = expected[dest]
        require(mount.get("Type") == mount_type and mount.get("RW") is writable,
                f"Unexpected mount type or access at {dest}")
        if mount_type == "bind":
            actual = mount.get("Source", "")
            require(actual == source and os.path.realpath(actual) == source,
                    f"Unexpected or escaping bind source at {dest}")
            require(os.path.exists(source), f"Bind source does not exist: {source}")
            require(mount.get("Propagation") in ("", "rprivate"),
                    f"Shared mount propagation is forbidden at {dest}")
        else:
            require(mount.get("Name") == source, f"Unexpected volume at {dest}")
            check_volume(source, mount.get("Source", ""), docker_fs)
    require(set(expected).issubset(seen), "A required mount is absent.")


def inspect(kind, docker_fs):
    name = CONTAINERS[kind]
    data = json.loads(docker("container", "inspect", name).stdout)
    require(isinstance(data, list) and len(data) == 1, "Unexpected inspect response.")
    item = data[0]
    identity = item.get("Id", "")
    require(re.fullmatch(r"[0-9a-f]{64}", identity) is not None, "Invalid container ID.")
    require(item.get("Name") == "/" + name, "Unexpected container name.")
    config, host = item["Config"], item["HostConfig"]
    label = f"io.nexum.{kind}.workspace"
    require((config.get("Labels") or {}).get(label) == WORKSPACE,
            "Container workspace label does not match.")
    require(config.get("User", "") in ("", "0", "0:0", "root", "root:root"),
            "Unexpected entrypoint user.")
    require(config.get("Entrypoint") == ["/bin/sh"], "Unexpected entrypoint.")
    expected_cmd = (["-c", "exec sleep infinity"] if kind == "dev"
                    else ["/opt/alpine-stagenet.sh", "__run"])
    require(config.get("Cmd") == expected_cmd, "Unexpected container command.")
    require(host.get("Privileged") is False, "Privileged containers are forbidden.")
    require(host.get("NetworkMode") in ("default", "bridge", "none"), "Unexpected network mode.")
    require(host.get("PidMode", "") == "", "Host/shared PID namespace is forbidden.")
    require(host.get("IpcMode", "") in ("", "private"), "Host/shared IPC is forbidden.")
    require(host.get("UTSMode", "") == "", "Host/shared UTS namespace is forbidden.")
    require(host.get("UsernsMode", "") == "", "Explicit user namespace overrides are forbidden.")
    require(host.get("CgroupnsMode") == "private", "A private cgroup namespace is required.")
    security = host.get("SecurityOpt") or []
    require(isinstance(security, list) and all(option in (
        "no-new-privileges", "no-new-privileges=true", "no-new-privileges:true"
    ) for option in security), "Security profile overrides are forbidden.")
    require(MASKED_PATHS.issubset(host.get("MaskedPaths") or []), "Default system masks are absent.")
    require(READONLY_PATHS.issubset(host.get("ReadonlyPaths") or []), "Default readonly system paths are absent.")
    for field in ("Devices", "DeviceRequests", "DeviceCgroupRules", "CapAdd", "VolumesFrom", "Links"):
        require(not host.get(field), f"{field} must be empty.")
    require(not host.get("PortBindings") and not host.get("PublishAllPorts"),
            "Published ports are forbidden.")
    memory, cpus = host.get("Memory"), host.get("NanoCpus")
    require(type(memory) is int and 0 < memory <= (3 if kind == "dev" else 2) * 1024**3,
            "Memory limit is absent or too large.")
    require(type(cpus) is int and 0 < cpus <= (2 if kind == "dev" else 1) * 10**9,
            "CPU limit is absent or too large.")
    require(host.get("MemorySwap") == memory, "Additional or unlimited swap is forbidden.")
    pids = host.get("PidsLimit")
    require(type(pids) is int and 0 < pids <= 256, "PID limit is absent or too large.")
    check_mounts(kind, item.get("Mounts", []), docker_fs)
    return item


def dev_exec(item, argv, *, timeout=READ_TIMEOUT):
    require(item["State"].get("Running") is True, "Dev container is stopped; use start dev.")
    args = ["exec", "--user", f"{USER_UID}:{USER_GID}", "--workdir", "/work/nexum-core"]
    for key, value in DEV_ENV.items():
        args.extend(["--env", f"{key}={value}"])
    # Use the inspected immutable ID, so replacing a name cannot redirect exec.
    return docker(*args, item["Id"], *argv, capture=False, timeout=timeout, check=False).returncode


def summary(item):
    state = item["State"]
    return {"name": item["Name"][1:], "id": item["Id"][:12],
            "status": state.get("Status"), "running": state.get("Running"),
            "oom_killed": state.get("OOMKilled"), "exit_code": state.get("ExitCode"),
            "memory_bytes": item["HostConfig"]["Memory"],
            "nano_cpus": item["HostConfig"]["NanoCpus"]}


def status(docker_fs):
    output = {}
    for kind in CONTAINERS:
        try:
            item = inspect(kind, docker_fs)
            output[kind] = summary(item)
            if kind == "stagenet" and item["State"].get("Running"):
                rpc = docker("exec", "--user", "10001:10001", item["Id"],
                             "/usr/bin/curl", "--fail", "--silent", "--show-error",
                             "--max-time", "10", "--noproxy", "*",
                             "http://127.0.0.1:38081/get_info", check=False)
                if rpc.returncode == 0:
                    output[kind]["get_info"] = json.loads(rpc.stdout)
                    output[kind]["rpc_ready"] = True
                else:
                    output[kind].update(rpc_ready=False, readiness="RPC not ready; bootstrap or sync may still be starting.")
        except (Refused, KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
            output[kind] = {"available": False, "error": str(error)}
    print(json.dumps(output, indent=2, ensure_ascii=False))


def main(args):
    require(os.geteuid() == 0, "Use the installed root-owned helper through sudo.")
    if args in ([], ["help"], ["--help"], ["-h"]):
        print(USAGE, end="")
        return 0
    valid = (args in (["status"], ["storage-check"], ["services-start"]) or
             (len(args) == 2 and args[0] in ("logs", "start", "stop", "restart") and args[1] in CONTAINERS) or
             args == ["dev", "versions"] or
             (len(args) >= 3 and args[:2] == ["dev", "cargo"]))
    require(valid, USAGE.strip())
    docker_fs = check_storage()
    if args == ["storage-check"]:
        print(json.dumps({"storage_verified": True, "filesystem_device": docker_fs}))
        return 0
    if args == ["services-start"]:
        return services_start()
    if args == ["status"]:
        status(docker_fs)
        return 0
    kind = "dev" if args[0] == "dev" else args[1]
    item = inspect(kind, docker_fs)
    if args[0] == "logs":
        return docker("logs", "--tail", "120", item["Id"], capture=False, check=False).returncode
    if args[0] in ("start", "stop", "restart"):
        action = [args[0]]
        if args[0] != "start":
            action.extend(["--time", "120"])
        docker(*action, item["Id"], timeout=150)
        print(json.dumps({"action": args[0], "container": CONTAINERS[kind], "completed": True}))
        return 0
    if args[1] == "versions":
        return dev_exec(item, ["/bin/sh", "-c", VERSIONS])
    return dev_exec(item, ["/usr/local/cargo/bin/cargo", *args[2:]], timeout=None)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (Refused, KeyError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
