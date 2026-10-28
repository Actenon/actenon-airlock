import copy

import pytest

from actenon_airlock.common import AirlockError
from actenon_airlock.protected import Docker, _verify_container

MOUNTS = {
    "/airlock": {"rw": False, "type": "bind", "source": "/Users/test/control"},
    "/ipc": {"rw": False, "type": "volume", "source": "airlock-ipc-test"},
    "/workspace": {"rw": True, "type": "bind", "source": "/Users/test/workspace"},
}


def configuration():
    # Reproduce the distinct read-only and writable bind reports observed on
    # a real Docker Desktop acceptance run, including the exact VM path prefix.
    return {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "Devices": [],
            "DeviceRequests": None,
            "GroupAdd": None,
            "PortBindings": {},
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "IpcMode": "private",
            "PidsLimit": 128,
            "Memory": 1073741824,
            "NanoCpus": 2000000000,
        },
        "Config": {"User": "10000:10000"},
        "Mounts": [
            {
                "Destination": "/airlock",
                "RW": False,
                "Type": "bind",
                "Source": "/Users/test/control",
            },
            {"Destination": "/ipc", "RW": False, "Type": "volume", "Name": "airlock-ipc-test"},
            {
                "Destination": "/workspace",
                "RW": True,
                "Type": "bind",
                "Source": "/host_mnt/Users/test/workspace",
            },
        ],
    }


class Engine:
    def __init__(self, config=None, prefix="/host_mnt"):
        self.config = config or configuration()
        self.host_path_prefix = prefix

    def json(self, args):
        return [self.config]


def test_verified_desktop_bind_mapping_preserves_actual_evidence():
    result = _verify_container(Engine(), "agent-test", agent=True, mounts=MOUNTS)
    assert result["mounts"]["/workspace"]["source"] == "/host_mnt/Users/test/workspace"


def test_unverified_or_linux_engine_cannot_accept_a_desktop_alias():
    with pytest.raises(AirlockError):
        _verify_container(Engine(prefix=None), "agent-test", agent=True, mounts=MOUNTS)


@pytest.mark.parametrize(
    "attack",
    [
        "wrong-source",
        "double-prefix",
        "writable-control",
        "extra-mount",
        "wrong-volume",
        "missing-cpu",
        "host-network",
    ],
)
def test_desktop_mapping_cannot_weaken_the_required_boundary(attack):
    config = copy.deepcopy(configuration())
    if attack == "wrong-source":
        config["Mounts"][2]["Source"] = "/host_mnt/Users/test/other"
    elif attack == "double-prefix":
        config["Mounts"][2]["Source"] = "/host_mnt/host_mnt/Users/test/workspace"
    elif attack == "writable-control":
        config["Mounts"][0]["RW"] = True
    elif attack == "extra-mount":
        config["Mounts"].append(
            {
                "Destination": "/credentials",
                "RW": False,
                "Type": "bind",
                "Source": "/Users/test/.ssh",
            }
        )
    elif attack == "wrong-volume":
        config["Mounts"][1]["Name"] = "another-principals-volume"
    elif attack == "missing-cpu":
        config["HostConfig"].pop("NanoCpus")
    elif attack == "host-network":
        config["HostConfig"]["NetworkMode"] = "host"
    with pytest.raises(AirlockError):
        _verify_container(Engine(config), "agent-test", agent=True, mounts=MOUNTS)


@pytest.mark.parametrize(
    "platform,system,expected",
    [
        ("darwin", "Docker Desktop", "/host_mnt"),
        ("linux", "Docker Desktop", None),
        ("darwin", "Ubuntu", None),
    ],
)
def test_mapping_requires_both_local_macos_and_desktop_engine(
    monkeypatch, platform, system, expected
):
    monkeypatch.setattr("actenon_airlock.protected.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("actenon_airlock.protected.sys.platform", platform)
    docker = Docker()
    docker.environment = {}
    monkeypatch.setattr(
        docker,
        "json",
        lambda args, **kw: (
            [{"Endpoints": {"docker": {"Host": "unix:///local/docker.sock"}}}]
            if args[0] == "context"
            else {
                "OSType": "linux",
                "OperatingSystem": system,
                "SecurityOptions": ["name=seccomp,profile=builtin"],
                "ServerVersion": "test",
            }
        ),
    )
    docker.verify_engine()
    assert docker.host_path_prefix == expected
