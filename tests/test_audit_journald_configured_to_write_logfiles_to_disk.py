#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_journald_configured_to_write_logfiles_to_disk_pass(self, cmd):
    stdout = [
        'Storage=persistent',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_journald_configured_to_write_logfiles_to_disk_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_journald_configured_to_write_logfiles_to_disk_pass)
def test_audit_journald_configured_to_write_logfiles_to_disk_pass():
    state = test.audit_journald_configured_to_write_logfiles_to_disk()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_journald_configured_to_write_logfiles_to_disk_fail)
def test_audit_journald_configured_to_write_logfiles_to_disk_fail():
    state = test.audit_journald_configured_to_write_logfiles_to_disk()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
