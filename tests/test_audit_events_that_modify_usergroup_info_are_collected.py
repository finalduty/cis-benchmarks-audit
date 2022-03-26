#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_events_that_modify_usergroup_info_are_collected_pass(self, cmd):
    stdout = [
        '-w /etc/group -p wa -k identity',
        '-w /etc/passwd -p wa -k identity',
        '-w /etc/gshadow -p wa -k identity',
        '-w /etc/shadow -p wa -k identity',
        '-w /etc/security/opasswd -p wa -k identity',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_that_modify_usergroup_info_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_events_that_modify_usergroup_info_are_collected_pass)
def test_audit_events_that_modify_usergroup_info_are_collected_pass():
    state = test.audit_events_that_modify_usergroup_info_are_collected()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_events_that_modify_usergroup_info_are_collected_fail)
def test_audit_events_that_modify_usergroup_info_are_collected_fail():
    state = test.audit_events_that_modify_usergroup_info_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
