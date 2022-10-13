#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

import cis_audit

test = cis_audit.CISAudit()


def mock_audit_file_permissions_pass(*args, **kwargs):
    return 0


def mock_audit_file_permissions_fail(*args, **kwargs):
    return 1


def mock_shellexec(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = [
        'hostkey /pytest1',
        'hostkey /pytest2',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(cis_audit.CISAudit, "_shellexec", mock_shellexec)
@patch.object(cis_audit.CISAudit, "audit_file_permissions", mock_audit_file_permissions_pass)
def test_audit_permissions_on_public_host_key_files_pass():
    state = test.audit_permissions_on_public_host_key_files()
    assert state == 0


@patch.object(cis_audit.CISAudit, "_shellexec", mock_shellexec)
@patch.object(cis_audit.CISAudit, "audit_file_permissions", mock_audit_file_permissions_fail)
def test_audit_permissions_on_public_host_key_files_fail():
    state = test.audit_permissions_on_public_host_key_files()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
