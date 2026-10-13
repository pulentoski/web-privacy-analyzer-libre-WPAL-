"""v1.4: el worker publica sus contadores de cgroup v2 (solo lectura, sin docker.sock)."""

import os
import pathlib

from app import resources


def test_worker_reads_its_own_cgroup_counters():
    sample = resources.read_sample()
    assert set(sample) == set(resources.SAMPLE_KEYS)
    assert sample["memory_current"] > 0 and sample["cpu_usage_usec"] > 0 and sample["pids_current"] >= 1
    # Límites que pone docker-compose.yml al worker: memoria, CPU y pids.
    assert sample["memory_max"] and sample["memory_max"] > sample["memory_current"]
    assert sample["cpu_quota_usec"] and sample["cpu_period_usec"] and sample["pids_max"]
    assert resources.clean_sample(sample) == sample


def test_cgroup_is_read_only_and_there_is_no_docker_socket():
    assert not os.access("/sys/fs/cgroup/memory.max", os.W_OK)
    for path in ("/var/run/docker.sock", "/run/docker.sock"):
        assert not pathlib.Path(path).exists()


def test_sample_written_by_another_service_is_validated():
    good = {key: 1 for key in resources.SAMPLE_KEYS}
    assert resources.clean_sample({**good, "otra": "<script>"}) == good
    assert resources.clean_sample({**good, "memory_max": None})["memory_max"] is None
    for hostile in (None, "x", [good], {**good, "memory_current": "9"}, {**good, "cpu_usage_usec": -5}, {**good, "ts": None}, {**good, "pids_current": True}):
        assert resources.clean_sample(hostile) is None
