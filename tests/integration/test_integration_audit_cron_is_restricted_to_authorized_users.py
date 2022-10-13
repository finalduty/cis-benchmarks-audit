#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    shellexec('install -o root -g root -m 0600 /dev/null /etc/cron.allow')
    if os.path.exists('/etc/cron.deny'):
        os.remove('/etc/cron.deny')

    yield None

    os.remove('/etc/cron.allow')


@pytest.fixture()
def setup_to_fail_exists():
    shellexec('touch /etc/cron.deny')
    if os.path.exists('/etc/cron.allow'):
        os.remove('/etc/cron.allow')

    yield None

    os.remove('/etc/cron.deny')


@pytest.fixture()
def setup_to_fail_permissions():
    shellexec('touch /etc/cron.allow')
    if os.path.exists('/etc/cron.deny'):
        os.remove('/etc/cron.deny')

    yield None

    os.remove('/etc/cron.allow')


def test_integration_audit_cron_is_restricted_to_authorized_users_pass(setup_to_pass):
    state = CISAudit().audit_cron_is_restricted_to_authorized_users()
    assert state == 0


def test_integration_audit_cron_is_restricted_to_authorized_users_fail_exists(setup_to_fail_exists):
    state = CISAudit().audit_cron_is_restricted_to_authorized_users()
    assert state == 3


def test_integration_audit_cron_is_restricted_to_authorized_users_fail_permissions(setup_to_fail_permissions):
    state = CISAudit().audit_cron_is_restricted_to_authorized_users()
    assert state == 4


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
