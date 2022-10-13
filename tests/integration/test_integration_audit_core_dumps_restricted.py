#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    shellexec('echo -e "*\thard\tcore\t0" > /etc/security/limits.d/pytest.conf')
    shellexec('echo 0 > /proc/sys/fs/suid_dumpable')
    shellexec('echo -e "fs.suid_dumpable = 0" > /etc/sysctl.d/pytest.conf')

    yield None

    os.remove('/etc/security/limits.d/pytest.conf')
    os.remove('/etc/sysctl.d/pytest.conf')


@pytest.fixture()
def setup_to_fail():
    shellexec('echo 1 > /proc/sys/fs/suid_dumpable')


def test_integration_audit_core_dumps_restricted_pass_with_tabs(setup_to_pass):
    state = CISAudit().audit_core_dumps_restricted()
    assert state == 0


def test_integration_audit_core_dumps_restricted_fail(setup_to_fail):
    state = CISAudit().audit_core_dumps_restricted()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
