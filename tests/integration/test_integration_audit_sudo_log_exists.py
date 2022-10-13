#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit


@pytest.fixture
def setup_to_pass():
    ## Setup
    with open('/etc/sudoers.d/pytest', 'w') as f:
        f.write('Defaults logfile="/var/log/sudo.log"\n')

    yield None

    ## Tear-down
    os.remove('/etc/sudoers.d/pytest')


def test_integration_audit_sudo_log_exists_pass(setup_to_pass):
    state = CISAudit().audit_sudo_log_exists()
    assert state == 0


def test_integration_audit_sudo_log_exists_fail():
    state = CISAudit().audit_sudo_log_exists()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
