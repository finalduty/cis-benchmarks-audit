#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shutil.copy('/etc/default/useradd', '/etc/default/useradd.bak')
    shutil.copy('/etc/shadow', '/etc/shadow.bak')

    shellexec("sed -i '/INACTIVE/ s/=.*/=30/' /etc/default/useradd")
    shellexec("sed -i -E '/(root|vagrant):/ s/0:99999:7::/0:99999:7:30:/' /etc/shadow")

    yield None

    ## Tear-down
    shutil.move('/etc/default/useradd.bak', '/etc/default/useradd')
    shutil.move('/etc/shadow.bak', '/etc/shadow')


def test_integration_audit_password_inactive_lock_is_configured_pass(setup_to_pass):
    state = CISAudit().audit_password_inactive_lock_is_configured()
    assert state == 0


def test_integration_audit_password_inactive_lock_is_configured_pass_fail():
    state = CISAudit().audit_password_inactive_lock_is_configured()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
