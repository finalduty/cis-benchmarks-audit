#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_audit_logs_not_automatically_deleted_pass(self, cmd):
    stdout = ['max_log_file = keep_logs', '']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_logs_not_automatically_deleted_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_audit_logs_not_automatically_deleted_pass)
def test_audit_audit_logs_not_automatically_deleted_pass():
    state = test.audit_audit_logs_not_automatically_deleted()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_logs_not_automatically_deleted_fail)
def test_audit_audit_logs_not_automatically_deleted_fail():
    state = test.audit_audit_logs_not_automatically_deleted()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
