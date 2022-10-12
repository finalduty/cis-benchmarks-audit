#!/usr/bin/env python3

import shutil
import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec('yum update -y')

    yield None


@pytest.fixture
def setup_to_fail():
    shellexec('yum downgrade -y linux-firmware')

    yield None


@pytest.fixture
def setup_to_error():
    shutil.move('/etc/yum.repos.d', '/etc/yum.repos.d.bak')

    yield None

    shutil.move('/etc/yum.repos.d.bak', '/etc/yum.repos.d')


def test_integration_audit_updates_installed_pass(setup_to_pass):
    state = CISAudit().audit_updates_installed()
    assert state == 0


def test_integration_audit_updates_installed_fail(setup_to_fail):
    state = CISAudit().audit_updates_installed()
    assert state == 1


def test_integration_audit_updates_installed_error(setup_to_error):
    state = CISAudit().audit_updates_installed()
    assert state == -1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
