#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    ## Original State
    is_active = shellexec('systemctl is-active chronyd').stdout[0]
    is_enabled = shellexec('systemctl is-enabled chronyd').stdout[0]
    shutil.copy('/etc/chrony.conf', '/etc/chrony.conf.bak')

    ## Setup
    shellexec('systemctl stop chronyd')
    shellexec('systemctl disable chronyd')
    shellexec('sed -i "/^server/d" /etc/chrony.conf')

    yield None

    ## Cleanup
    if is_active == 'active':
        shellexec('systemctl start chronyd')

    if is_enabled == 'enabled':
        shellexec('systemctl enable chronyd')

    shutil.move('/etc/chrony.conf.bak', '/etc/chrony.conf')


def test_integration_audit_chrony_is_configured_pass():
    state = CISAudit().audit_chrony_is_configured()
    assert state == 0


def test_integration_audit_chrony_is_configured_fail(setup_to_fail):
    state = CISAudit().audit_chrony_is_configured()
    assert state == 15


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
