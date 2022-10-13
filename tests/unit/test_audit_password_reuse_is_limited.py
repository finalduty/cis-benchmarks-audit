#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_password_reuse_is_limited_pass(*args):
    returncode = 0
    stderr = ['']
    stdout = [
        '/etc/pam.d/system-auth:password required pam_pwhistory.so remember=5',
        '/etc/pam.d/password-auth:password required pam_pwhistory.so remember=5',
        '',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_reuse_is_limited_fail(*args):
    returncode = 1
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_password_reuse_is_limited_pass)
def test_audit_password_reuse_is_limited_pass():
    state = test.audit_password_reuse_is_limited()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_password_reuse_is_limited_fail)
def test_audit_password_reuse_is_limited_pass_fail():
    state = test.audit_password_reuse_is_limited()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
