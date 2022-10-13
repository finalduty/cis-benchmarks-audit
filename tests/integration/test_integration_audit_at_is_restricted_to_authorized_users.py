#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    ## Setup
    shellexec('rm /etc/at.deny')
    shellexec('install -m 0600 /dev/null /etc/at.allow')

    yield None

    ## Cleanup
    shellexec('rm /etc/at.allow')


@pytest.fixture()
def setup_to_fail():
    ## Setup
    shellexec('touch /etc/at.deny')
    shellexec('rm /etc/at.allow')

    yield None

    ## Cleanup
    shellexec('/etc/at.deny')


def test_integrate_audit_at_is_restricted_to_authorized_users_pass(setup_to_pass):
    state = CISAudit().audit_at_is_restricted_to_authorized_users()
    assert state == 0


def test_integrate_audit_at_is_restricted_to_authorized_users_fail(setup_to_fail):
    state = CISAudit().audit_at_is_restricted_to_authorized_users()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
