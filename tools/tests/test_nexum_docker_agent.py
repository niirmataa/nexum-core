"""Offline tests of the broker's host privilege boundary; no Docker or sudo."""
import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HELPER_PATH = Path(__file__).resolve().parents[1] / "nexum-docker-agent.py"
SPEC = importlib.util.spec_from_file_location("nexum_docker_agent_under_test", HELPER_PATH)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)

CONTAINER_ID = "a1" * 32
VOLUME_NAME = "nexum-alpine-dev-cache"
VOLUME_PATH = f"/data/docker/volumes/{VOLUME_NAME}/_data"
DATA_DEVICE = 42
APPROVED_ROOT_BASE = "/var/lib/nexum-docker"
APPROVED_ROOT_UUID = "09929a1b-d005-4a5a-9fe3-29ab45851965"


def dev_container():
    """A legitimate existing container, independent of the helper's allowlist."""
    return {
        "Id": CONTAINER_ID,
        "Name": "/nexum-alpine-dev",
        "Config": {
            "Labels": {"io.nexum.dev.workspace": agent.WORKSPACE},
            "User": "",
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", "exec sleep infinity"],
        },
        "State": {"Running": True, "Status": "running", "ExitCode": 0},
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "SecurityOpt": ["no-new-privileges"],
            "MaskedPaths": [
                "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore",
                "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
                "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
                "/sys/firmware", "/sys/devices/virtual/powercap",
            ],
            "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
            "PortBindings": {},
            "PublishAllPorts": False,
            "Memory": 3 * 1024**3,
            "MemorySwap": 3 * 1024**3,
            "NanoCpus": 2 * 10**9,
            "PidsLimit": 256,
        },
        "Mounts": [
            {"Type": "bind", "Source": agent.WORKSPACE,
             "Destination": "/work/nexum-core", "RW": True, "Propagation": "rprivate"},
            {"Type": "bind", "Source": agent.WORKSPACE + "/_incoming/privAI",
             "Destination": "/work/privAI", "RW": False, "Propagation": "rprivate"},
            {"Type": "volume", "Name": VOLUME_NAME, "Source": VOLUME_PATH,
             "Destination": "/cache", "RW": True},
        ],
    }


class BrokerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.item = dev_container()
        self.volume = {"Name": VOLUME_NAME, "Driver": "local", "Scope": "local",
                       "Options": None, "Mountpoint": VOLUME_PATH}
        self.devices = {"/": 1}
        self.calls = []
        self.host_calls = []
        self.operations = []
        self.exec_returncode = 0
        self.containerd_root = "/data/containerd"
        self.findmnt_output = f"{APPROVED_ROOT_UUID} ext4\n"
        self.findmnt_returncode = 0
        self.path_metadata = {}
        self.config_patch = patch.object(agent, "docker_root_from_config", return_value="/data/docker")
        self.config = self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        patches = [
            patch.object(agent, "docker", side_effect=self.fake_docker),
            patch.object(agent.subprocess, "run", side_effect=self.fake_subprocess),
            patch.object(agent.os, "geteuid", return_value=0),
            patch.object(agent.os, "stat", side_effect=self.fake_stat),
            patch.object(agent.os, "lstat", side_effect=self.fake_stat),
            patch.object(agent.os.path, "realpath", side_effect=lambda path: path),
            patch.object(agent.os.path, "exists", return_value=True),
            patch.object(agent.os.path, "isdir", return_value=True),
        ]
        for replacement in patches:
            replacement.start()
            self.addCleanup(replacement.stop)

    def fake_stat(self, path, *args, **kwargs):
        path = str(path)
        metadata = {"st_dev": self.devices.get(path, DATA_DEVICE),
                    "st_uid": 0, "st_mode": stat.S_IFDIR | 0o755}
        metadata.update(self.path_metadata.get(path, {}))
        return SimpleNamespace(**metadata)

    def fake_subprocess(self, argv, **kwargs):
        self.host_calls.append(argv)
        if argv == ["/usr/bin/containerd", "--config", "/etc/containerd/config.toml", "config", "dump"]:
            output = f"version = 2\nroot = {json.dumps(self.containerd_root)}\n"
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv == ["/usr/bin/findmnt", "--noheadings", "--raw", "--output", "UUID,FSTYPE",
                    "--target", APPROVED_ROOT_BASE]:
            return subprocess.CompletedProcess(argv, self.findmnt_returncode,
                                               self.findmnt_output, "")
        self.fail(f"Unexpected host invocation: {argv!r}")

    def use_approved_root_storage(self):
        """Model the specifically approved Micron root, not an arbitrary root path."""
        docker_root = APPROVED_ROOT_BASE + "/docker"
        self.config.return_value = docker_root
        self.containerd_root = APPROVED_ROOT_BASE + "/containerd"
        volume_path = f"{docker_root}/volumes/{VOLUME_NAME}/_data"
        self.volume["Mountpoint"] = volume_path
        self.item["Mounts"][2]["Source"] = volume_path
        self.devices = {path: 1 for path in ("/", "/var", "/var/lib", APPROVED_ROOT_BASE,
                                           docker_root, self.containerd_root, volume_path)}

    def fake_docker(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args == ("container", "inspect", "nexum-alpine-dev"):
            output = [self.item]
        elif args == ("volume", "inspect", VOLUME_NAME):
            output = [self.volume]
        elif args[0] in {"exec", "start", "stop", "restart", "logs"}:
            self.operations.append((args, kwargs))
            return subprocess.CompletedProcess(args, self.exec_returncode, "", "")
        else:
            self.fail(f"Unexpected Docker invocation: {args!r}")
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")

    def assert_start_refused(self):
        with self.assertRaises(agent.Refused):
            agent.main(["start", "dev"])
        self.assertEqual(self.operations, [], "Rejected containers must never be operated on")

    def test_unknown_actions_names_and_extra_arguments_never_reach_docker(self):
        attempts = [
            ["run", "dev"], ["create", "dev"], ["rm", "dev"], ["exec", "dev", "sh"],
            ["start", "other"], ["logs", "--privileged"], ["restart", "nexum-alpine-dev"],
            ["status", "--host=tcp://example.invalid"], ["dev", "sh"],
            ["services-start", "ssh.service"], ["services-start", "--now"],
            ["services-start", "containerd.service", "docker.service"],
            ["storage-check", "--skip-validation"],
            ["dev", "cargo"], ["start", "dev", "--privileged"], ["stagenet", "cargo", "test"],
        ]
        for args in attempts:
            with self.subTest(args=args), self.assertRaises(agent.Refused):
                agent.main(args)
        self.assertEqual(self.calls, [])
        self.config.assert_not_called()
        agent.subprocess.run.assert_not_called()

    def test_non_root_caller_is_rejected_before_docker(self):
        with patch.object(agent.os, "geteuid", return_value=1000):
            self.assert_start_refused()
            with self.assertRaises(agent.Refused):
                agent.main(["services-start"])
            with self.assertRaises(agent.Refused):
                agent.main(["storage-check"])
        self.assertEqual(self.calls, [])
        self.config.assert_not_called()
        agent.subprocess.run.assert_not_called()

    def test_a_valid_container_is_operated_on_by_immutable_id(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(["start", "dev"]), 0)
        self.assertEqual(self.operations[0][0], ("start", CONTAINER_ID))
        self.assertIn(("volume", "inspect", VOLUME_NAME), [args for args, _ in self.calls])

    def test_privileged_host_namespaces_and_published_ports_are_rejected(self):
        unsafe = [
            ("Privileged", True), ("NetworkMode", "host"), ("PidMode", "host"),
            ("IpcMode", "host"), ("UTSMode", "host"), ("CgroupnsMode", "host"),
            ("PortBindings", {"2375/tcp": [{"HostPort": "2375"}]}), ("PublishAllPorts", True),
            ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", ["seccomp=unconfined"]),
        ]
        for field, value in unsafe:
            with self.subTest(field=field):
                self.item = dev_container()
                self.item["HostConfig"][field] = value
                self.assert_start_refused()

    def test_an_extra_docker_socket_mount_is_rejected(self):
        self.item["Mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock",
                                    "Destination": "/var/run/docker.sock", "RW": True})
        self.assert_start_refused()

    def test_missing_or_excessive_resource_limits_are_rejected(self):
        unsafe = [
            ("Memory", 0), ("Memory", 4 * 1024**3),
            ("NanoCpus", 0), ("NanoCpus", 3 * 10**9),
            ("PidsLimit", None), ("PidsLimit", 257), ("PidsLimit", True),
            ("MemorySwap", -1), ("MemorySwap", 4 * 1024**3),
        ]
        for field, value in unsafe:
            with self.subTest(field=field, value=value):
                self.item = dev_container()
                self.item["HostConfig"][field] = value
                self.assert_start_refused()

    def test_a_named_volume_cannot_hide_a_host_bind_mount(self):
        self.volume["Options"] = {"type": "none", "o": "bind", "device": "/"}
        self.assert_start_refused()

    def test_volume_storage_must_be_on_the_verified_data_filesystem(self):
        self.devices[VOLUME_PATH] = 1
        self.assert_start_refused()

    def test_a_volume_mountpoint_cannot_be_an_arbitrary_directory_on_the_same_filesystem(self):
        for path in ("/data/other", "/data/docker/volumes/other/_data",
                     f"/data/docker/volumes/{VOLUME_NAME}/different"):
            with self.subTest(path=path):
                self.volume["Mountpoint"] = path
                self.item["Mounts"][2]["Source"] = path
                self.assert_start_refused()

    def test_docker_and_containerd_storage_cannot_fall_back_to_root(self):
        for path, device in [("/data/docker", 1), ("/data/containerd", 99)]:
            with self.subTest(path=path):
                self.devices = {"/": 1, path: device}
                self.assert_start_refused()

    def test_only_the_approved_root_storage_can_operate_on_a_container(self):
        self.use_approved_root_storage()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(["start", "dev"]), 0)
        self.assertEqual(self.operations[0][0], ("start", CONTAINER_ID))
        self.assertIn(["/usr/bin/findmnt", "--noheadings", "--raw", "--output", "UUID,FSTYPE",
                       "--target", APPROVED_ROOT_BASE], self.host_calls)

    def test_storage_check_validates_approved_root_without_calling_docker_or_starting_services(self):
        self.use_approved_root_storage()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(agent.main(["storage-check"]), 0)
        self.assertEqual(json.loads(output.getvalue()), {
            "storage_verified": True, "filesystem_device": 1,
        })
        self.assertEqual(self.calls, [])
        self.assertEqual(self.operations, [])
        self.assertEqual(self.host_calls, [
            ["/usr/bin/containerd", "--config", "/etc/containerd/config.toml", "config", "dump"],
            ["/usr/bin/findmnt", "--noheadings", "--raw", "--output", "UUID,FSTYPE",
             "--target", APPROVED_ROOT_BASE],
        ])

    def test_root_storage_requires_the_exact_approved_docker_and_containerd_paths(self):
        self.use_approved_root_storage()
        for docker_root, containerd_root in (
            ("/var/lib/other/docker", APPROVED_ROOT_BASE + "/containerd"),
            (APPROVED_ROOT_BASE + "/docker-other", APPROVED_ROOT_BASE + "/containerd"),
            (APPROVED_ROOT_BASE + "/docker", "/var/lib/other/containerd"),
            (APPROVED_ROOT_BASE + "/docker", APPROVED_ROOT_BASE + "/containerd-other"),
        ):
            with self.subTest(docker=docker_root, containerd=containerd_root):
                self.config.return_value = docker_root
                self.containerd_root = containerd_root
                self.devices[docker_root] = self.devices[containerd_root] = 1
                self.assert_start_refused()

    def test_root_storage_requires_the_approved_uuid_and_ext4_with_one_unambiguous_mount(self):
        self.use_approved_root_storage()
        outputs = ("", "another-uuid ext4\n", f"{APPROVED_ROOT_UUID} xfs\n",
                   f"{APPROVED_ROOT_UUID} ext4\n{APPROVED_ROOT_UUID} ext4\n",
                   f"{APPROVED_ROOT_UUID} ext4 unexpected\n")
        for output in outputs:
            with self.subTest(output=output):
                self.findmnt_output = output
                self.assert_start_refused()
        self.findmnt_output = f"{APPROVED_ROOT_UUID} ext4\n"
        self.findmnt_returncode = 1
        self.assert_start_refused()

    def test_root_storage_rejects_untrusted_writable_symlink_or_nondirectory_parents(self):
        self.use_approved_root_storage()
        paths = ("/var", "/var/lib", APPROVED_ROOT_BASE,
                 APPROVED_ROOT_BASE + "/docker", APPROVED_ROOT_BASE + "/containerd")
        unsafe = ({"st_uid": 1000}, {"st_mode": stat.S_IFDIR | 0o775},
                  {"st_mode": stat.S_IFDIR | 0o757}, {"st_mode": stat.S_IFLNK | 0o777},
                  {"st_mode": stat.S_IFREG | 0o644})
        for path in paths:
            for metadata in unsafe:
                with self.subTest(path=path, metadata=metadata):
                    self.path_metadata = {path: metadata}
                    self.assert_start_refused()

    def test_missing_root_storage_directory_is_refused_without_docker(self):
        self.use_approved_root_storage()
        with patch.object(agent.os, "lstat", side_effect=FileNotFoundError("Missing approved storage")):
            self.assert_start_refused()
        self.assertEqual(self.calls, [])

    def test_approved_root_storage_does_not_allow_a_different_volume_directory(self):
        self.use_approved_root_storage()
        self.volume["Mountpoint"] = "/var/lib/unrelated"
        self.item["Mounts"][2]["Source"] = "/var/lib/unrelated"
        self.devices["/var/lib/unrelated"] = 1
        self.assert_start_refused()

    def test_default_proc_masks_and_readonly_paths_cannot_be_removed(self):
        for field, required_path in [("MaskedPaths", "/proc/kcore"), ("ReadonlyPaths", "/proc/sys")]:
            with self.subTest(field=field):
                self.item = dev_container()
                self.item["HostConfig"][field].remove(required_path)
                self.assert_start_refused()

    def test_cargo_arguments_are_literal_and_cannot_become_docker_flags_or_host_shell(self):
        cargo_args = ["test", "--", "--privileged", "--user=0:0", "-H", "tcp://example.invalid",
                      "--env=PATH=/evil", "two words", "$(touch /host)", "; touch /host"]
        self.exec_returncode = 37
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://example.invalid", "PATH": "/evil"}):
            self.assertEqual(agent.main(["dev", "cargo", *cargo_args]), 37)
        self.assertEqual(len(self.operations), 1)
        argv, kwargs = self.operations[0]
        self.assertEqual(argv[:5], ("exec", "--user", "1000:1000", "--workdir", "/work/nexum-core"))
        identity_index = argv.index(CONTAINER_ID)
        self.assertEqual(argv[identity_index + 1:], ("/usr/local/cargo/bin/cargo", *cargo_args))
        options = argv[5:identity_index]
        self.assertEqual(options[::2], ("--env",) * (len(options) // 2))
        environment = dict(value.split("=", 1) for value in options[1::2])
        self.assertEqual(environment["PATH"], "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin")
        self.assertEqual(environment["HOME"], "/cache/home")
        self.assertEqual(environment["CARGO_HOME"], "/cache/cargo")
        self.assertEqual(environment["CARGO_TARGET_DIR"], "/cache/target")
        self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "1.94.0")
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("/bin/sh", argv)
        self.assertEqual(kwargs, {"capture": False, "timeout": None, "check": False})


class HostExecutionEnvironmentTests(unittest.TestCase):
    def test_docker_cli_uses_an_absolute_binary_local_socket_and_clean_environment(self):
        result = subprocess.CompletedProcess([], 0, "{}", "")
        hostile = {"PATH": "/attacker/bin", "DOCKER_HOST": "tcp://example.invalid:2375",
                   "DOCKER_CONTEXT": "attacker", "HOME": "/attacker", "LD_PRELOAD": "/evil.so"}
        with patch.dict(os.environ, hostile), patch.object(agent.subprocess, "run", return_value=result) as run:
            self.assertIs(agent.docker("info"), result)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "info"])
        self.assertEqual(run.call_args.kwargs["env"], {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C.UTF-8",
        })
        self.assertEqual(run.call_args.kwargs["cwd"], "/")
        self.assertFalse(run.call_args.kwargs.get("shell", False))


class RootDockerConfigTests(unittest.TestCase):
    class ConfigStream(io.BytesIO):
        def __init__(self, body):
            super().__init__(body)
            self.read_sizes = []

        def fileno(self):
            return 47

        def read(self, size=-1):
            self.read_sizes.append(size)
            return super().read(size)

    @contextlib.contextmanager
    def config(self, body=b'{"data-root":"/data/docker"}', *, uid=0,
               mode=stat.S_IFREG | 0o644, reported_size=None,
               realpath=None, isdir=True):
        """Supply every descriptor and filesystem result without touching /etc."""
        stream = self.ConfigStream(body)
        metadata = SimpleNamespace(st_uid=uid, st_mode=mode,
                                   st_size=len(body) if reported_size is None else reported_size)
        with patch.object(agent.os, "open", return_value=47) as opened, \
                patch.object(agent.os, "fdopen", return_value=stream) as fdopen, \
                patch.object(agent.os, "fstat", return_value=metadata) as fstat, \
                patch.object(agent.os.path, "realpath", side_effect=realpath or (lambda path: path)), \
                patch.object(agent.os.path, "isdir", return_value=isdir), \
                patch.object(agent.subprocess, "run", side_effect=AssertionError("Config read must not spawn a process")):
            yield stream, opened, fdopen, fstat

    def test_config_uses_fixed_file_nofollow_and_checked_descriptor_despite_hostile_environment(self):
        hostile = {"DOCKER_HOST": "tcp://attacker.invalid:2375", "DOCKER_CONTEXT": "attacker",
                   "DOCKER_CONFIG": "/attacker/config", "HOME": "/attacker", "PATH": "/attacker/bin"}
        with patch.dict(os.environ, hostile), self.config() as (stream, opened, fdopen, fstat):
            self.assertEqual(agent.docker_root_from_config(), "/data/docker")
        opened.assert_called_once_with("/etc/docker/daemon.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        fdopen.assert_called_once_with(47, "rb")
        fstat.assert_called_once_with(47)
        self.assertEqual(stream.read_sizes, [64 * 1024 + 1])
        self.assertTrue(stream.closed)

    def test_symlinks_nonregular_files_untrusted_owners_and_writable_configs_are_rejected(self):
        # A symlink rejection is supplied by the mocked O_NOFOLLOW open; no real
        # filesystem link or privileged path is used by this test.
        with self.config() as (stream, opened, fdopen, fstat):
            opened.side_effect = OSError(errno.ELOOP, "Too many levels of symbolic links")
            with self.assertRaises(OSError):
                agent.docker_root_from_config()
            fdopen.assert_not_called()
            fstat.assert_not_called()
            self.assertEqual(stream.read_sizes, [])
            stream.close()
        for attrs in ({"uid": 1000}, {"mode": stat.S_IFREG | 0o664},
                      {"mode": stat.S_IFREG | 0o646}, {"mode": stat.S_IFIFO | 0o600},
                      {"mode": stat.S_IFDIR | 0o755}):
            with self.subTest(attrs=attrs), self.config(**attrs) as (stream, _, _, _):
                with self.assertRaises(agent.Refused):
                    agent.docker_root_from_config()
                self.assertEqual(stream.read_sizes, [])
                self.assertTrue(stream.closed)

    def test_config_must_contain_a_json_object(self):
        for body in (b"{not valid JSON", b"[]", b"null", b'"/data/docker"', b"42"):
            with self.subTest(body=body), self.config(body) as (stream, _, _, _):
                with self.assertRaises((agent.Refused, ValueError)):
                    agent.docker_root_from_config()
                self.assertTrue(stream.closed)

    def test_oversized_config_is_refused_by_metadata_and_by_the_bounded_read(self):
        with self.config(reported_size=64 * 1024 + 1) as (stream, _, _, _):
            with self.assertRaises(agent.Refused):
                agent.docker_root_from_config()
            self.assertEqual(stream.read_sizes, [])
            self.assertTrue(stream.closed)
        # Valid JSON plus whitespace makes a missing bound pass JSON decoding;
        # stale descriptor metadata must not bypass the actual byte limit.
        body = b'{"data-root":"/data/docker"}' + b" " * (64 * 1024 + 1)
        with self.config(body, reported_size=1) as (stream, _, _, _):
            with self.assertRaises(agent.Refused):
                agent.docker_root_from_config()
            self.assertEqual(stream.read_sizes, [64 * 1024 + 1])
            self.assertTrue(stream.closed)

    def test_data_root_must_be_an_absolute_canonical_existing_directory(self):
        for config in ({}, {"data-root": "relative/path"}, {"data-root": None},
                       {"data-root": 42}, {"data-root": True}):
            with self.subTest(config=config), self.config(json.dumps(config).encode()) as (stream, _, _, _):
                with self.assertRaises(agent.Refused):
                    agent.docker_root_from_config()
                self.assertTrue(stream.closed)
        for attrs in ({"realpath": lambda path: "/different/docker"}, {"isdir": False}):
            with self.subTest(attrs=attrs), self.config(**attrs) as (stream, _, _, _):
                with self.assertRaises(agent.Refused):
                    agent.docker_root_from_config()
                self.assertTrue(stream.closed)


class HostServicesTests(unittest.TestCase):
    def test_services_start_validates_storage_before_starting_only_the_literal_service_allowlist(self):
        events = []
        expected = [
            ["/usr/bin/systemctl", "start", "containerd.service", "docker.service"],
            ["/usr/bin/systemctl", "is-active", "containerd.service", "docker.service"],
        ]

        def storage():
            events.append("storage-validated")
            return DATA_DEVICE

        def command(argv, **kwargs):
            self.assertEqual(argv, expected[len(events) - 1])
            events.append(argv)
            return subprocess.CompletedProcess(argv, 0, "active\nactive\n", "")

        output = io.StringIO()
        hostile = {"PATH": "/attacker/bin", "SYSTEMD_UNIT_PATH": "/attacker/units",
                   "LD_PRELOAD": "/evil.so", "DOCKER_HOST": "tcp://attacker.invalid:2375"}
        with patch.object(agent.os, "geteuid", return_value=0), \
                patch.object(agent, "check_storage", side_effect=storage), \
                patch.object(agent, "docker", side_effect=AssertionError("Service start must not call Docker")), \
                patch.object(agent.subprocess, "run", side_effect=command) as run, \
                patch.dict(os.environ, hostile), contextlib.redirect_stdout(output):
            self.assertEqual(agent.main(["services-start"]), 0)
        self.assertEqual(events, ["storage-validated", *expected])
        self.assertEqual(json.loads(output.getvalue()), {
            "action": "services-start", "services": ["containerd.service", "docker.service"], "active": True,
        })
        for invocation in run.call_args_list:
            self.assertEqual(invocation.kwargs["env"], {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C.UTF-8",
            })
            self.assertEqual(invocation.kwargs["cwd"], "/")
            self.assertEqual(invocation.kwargs["timeout"], 60)
            self.assertFalse(invocation.kwargs.get("shell", False))

    def test_services_start_never_starts_a_service_when_storage_is_refused(self):
        with patch.object(agent.os, "geteuid", return_value=0), \
                patch.object(agent, "check_storage", side_effect=agent.Refused("Storage is on /")) as storage, \
                patch.object(agent.subprocess, "run") as run, patch.object(agent, "docker") as docker:
            with self.assertRaises(agent.Refused):
                agent.main(["services-start"])
        storage.assert_called_once_with()
        run.assert_not_called()
        docker.assert_not_called()

    def test_failed_service_start_or_active_check_cannot_report_success(self):
        for failing_call in (0, 1):
            results = [subprocess.CompletedProcess([], 0, "active\nactive\n", "") for _ in range(2)]
            results[failing_call] = subprocess.CompletedProcess([], 1, "", "Service failed")
            output = io.StringIO()
            with self.subTest(failing_call=failing_call), \
                    patch.object(agent.os, "geteuid", return_value=0), \
                    patch.object(agent, "check_storage", return_value=DATA_DEVICE), \
                    patch.object(agent.subprocess, "run", side_effect=results) as run, \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(agent.Refused):
                    agent.main(["services-start"])
            self.assertEqual(run.call_count, failing_call + 1)
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
