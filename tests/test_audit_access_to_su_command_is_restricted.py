#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from unittest.mock import patch
from types import SimpleNamespace

test = CISAudit()


def mock_access_to_su_command_is_restricted_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if '/etc/pam.d/su' in cmd:
        stdout = ['auth required pam_wheel.so use_uid group=<group_name>']
    elif '/etc/group' in cmd:
        stdout = ['pytest:x:1000:']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_access_to_su_command_not_restricted_fail(self, cmd):
    returncode = 0
    stderr = ['']

    if '/etc/pam.d/su' in cmd:
        stdout = ['']
    elif '/etc/group' in cmd:
        stdout = ['pytest:x:1000:pyuser']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_access_to_su_command_is_restricted_fail_with_users_in_group(self, cmd):
    returncode = 0
    stderr = ['']

    if '/etc/pam.d/su' in cmd:
        stdout = ['auth required pam_wheel.so use_uid group=<group_name>']
    elif '/etc/group' in cmd:
        stdout = ['pytest:x:1000:pyuser']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_access_to_su_command_is_restricted_pass)
def test_audit_access_to_su_command_is_restricted_pass():
    state = test.audit_access_to_su_command_is_restricted()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_access_to_su_command_not_restricted_fail)
def test_audit_access_to_su_command_is_restricted_fail():
    state = test.audit_access_to_su_command_is_restricted()
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_access_to_su_command_is_restricted_fail_with_users_in_group)
def test_audit_access_to_su_command_is_restricted_fail_with_users_in_group():
    state = test.audit_access_to_su_command_is_restricted()
    assert state == 2


if __name__ == '__main__':
    pytest.main([__file__])
