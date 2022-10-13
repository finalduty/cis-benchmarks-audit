#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_access_to_su_command_is_restricted_pass():
    ## Setup
    shellexec('echo "auth required pam_wheel.so use_uid group=pytest" >> /etc/pam.d/su')
    shellexec('echo "pytest:x:1000:" >> /etc/group')

    yield None

    ## Cleanup
    shellexec('sed -i "/pytest/d" /etc/pam.d/su')
    shellexec('sed -i "/pytest/d" /etc/group')


@pytest.fixture()
def setup_access_to_su_command_is_restricted_fail_with_no_users_in_group():
    ## Setup
    shellexec('echo "auth required pam_wheel.so use_uid group=pytest" >> /etc/pam.d/su')

    yield None

    ## Cleanup
    shellexec('sed -i "/pytest/d" /etc/pam.d/su')


def test_audit_access_to_su_command_is_restricted_pass(setup_access_to_su_command_is_restricted_pass):
    state = CISAudit().audit_access_to_su_command_is_restricted()
    assert state == 0


def test_audit_access_to_su_command_is_restricted_fail():
    state = CISAudit().audit_access_to_su_command_is_restricted()
    assert state == 1


def test_audit_access_to_su_command_is_restricted_fail_with_no_users_in_group(setup_access_to_su_command_is_restricted_fail_with_no_users_in_group):
    state = CISAudit().audit_access_to_su_command_is_restricted()
    assert state == 2


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
