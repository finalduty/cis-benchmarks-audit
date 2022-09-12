#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_journald_configured_to_compress_large_logs_pass(self, cmd):
    stdout = [
        'Compress=yes',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_journald_configured_to_compress_large_logs_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_journald_configured_to_compress_large_logs_pass)
def test_audit_journald_configured_to_compress_large_logs_pass():
    state = test.audit_journald_configured_to_compress_large_logs()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_journald_configured_to_compress_large_logs_fail)
def test_audit_journald_configured_to_compress_large_logs_fail():
    state = test.audit_journald_configured_to_compress_large_logs()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
