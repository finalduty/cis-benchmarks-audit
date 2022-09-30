#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail_yum_conf():
    shellexec("sed -i '/gpgcheck=/ s/1/0/' /etc/yum.conf")

    yield None

    shellexec("sed -i '/gpgcheck=/ s/0/1/' /etc/yum.conf")


@pytest.fixture
def setup_to_fail_repo_file():
    with open('/etc/yum.repos.d/pytest.repo', 'w') as f:
        f.writelines(
            [
                '[pytest]\n',
                'name=Pytest\n',
                'enabled=1\n',
                'gpgcheck=0\n',
            ]
        )

    yield None

    os.remove('/etc/yum.repos.d/pytest.repo')


def test_integration_audit_gpgcheck_is_activated_pass():
    state = CISAudit().audit_gpgcheck_is_activated()
    assert state == 0


def test_integration_audit_gpgcheck_is_activated_fail_state_1(setup_to_fail_yum_conf):
    state = CISAudit().audit_gpgcheck_is_activated()
    assert state == 1


def test_integration_audit_gpgcheck_is_activated_fail_state_2(setup_to_fail_repo_file):
    state = CISAudit().audit_gpgcheck_is_activated()
    assert state == 2


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
