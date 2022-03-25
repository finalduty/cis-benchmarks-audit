#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_audit_system_is_disabled_when_audit_logs_are_full_pass(self, cmd):
    if 'space_left_action' in cmd:
        stdout = ['space_left_action = email', '']
    elif 'action_mail_acct' in cmd:
        stdout = ['action_mail_acct = root', '']
    elif 'admin_space_left_action' in cmd:
        stdout = ['admin_space_left_action = halt', '']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_system_is_disabled_when_audit_logs_are_full_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_audit_system_is_disabled_when_audit_logs_are_full_pass)
def test_audit_system_is_disabled_when_audit_logs_are_full_pass():
    state = test.audit_system_is_disabled_when_audit_logs_are_full()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_system_is_disabled_when_audit_logs_are_full_fail)
def test_audit_system_is_disabled_when_audit_logs_are_full_fail():
    state = test.audit_system_is_disabled_when_audit_logs_are_full()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
