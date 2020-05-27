import contextlib
import os

import filelock
import pytest

from hypothesis import HealthCheck, settings


def pytest_configure(config):
    # HealthCheck.too_slow causes more trouble than good -- especially in CIs.
    settings.register_profile(
        "patience", settings(suppress_health_check=[HealthCheck.too_slow])
    )
    settings.load_profile("patience")


@pytest.fixture(scope="session")
def lock(tmp_path_factory):
    base_temp = tmp_path_factory.getbasetemp()
    lock_file = base_temp.parent / "serial.lock"
    yield filelock.FileLock(lock_file=str(lock_file))
    with contextlib.suppress(OSError):
        os.remove(path=lock_file)


@pytest.fixture()
def serial(lock):
    with lock.acquire(poll_intervall=0.1):
        yield
