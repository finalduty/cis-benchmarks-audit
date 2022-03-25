#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_events_for_successful_file_system_mounts_are_collected_pass(self, cmd):
    stdout = [
        '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
        '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_for_successful_file_system_mounts_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_events_for_successful_file_system_mounts_are_collected_pass)
def test_audit_events_for_successful_file_system_mounts_are_collected_pass():
    state = test.audit_events_for_successful_file_system_mounts_are_collected()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_events_for_successful_file_system_mounts_are_collected_fail)
def test_audit_events_for_successful_file_system_mounts_are_collected_fail():
    state = test.audit_events_for_successful_file_system_mounts_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
