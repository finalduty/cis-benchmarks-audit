#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_rsyslog_default_file_permission_is_configured_pass(self, cmd):
    stdout = [
        '$FileCreateMode 0640',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_rsyslog_default_file_permission_is_configured_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_rsyslog_default_file_permission_is_configured_pass)
def test_audit_rsyslog_default_file_permission_is_configured_pass():
    state = test.audit_rsyslog_default_file_permission_is_configured()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_rsyslog_default_file_permission_is_configured_fail)
def test_audit_rsyslog_default_file_permission_is_configured_fail():
    state = test.audit_rsyslog_default_file_permission_is_configured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
