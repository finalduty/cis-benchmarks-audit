#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from unittest.mock import patch
from types import SimpleNamespace

test = CISAudit()


def mock_password_hashing_algorithm_pass(*args):
    returncode = 0
    stderr = ['']
    stdout = [
        '/etc/pam.d/system-auth:password  sufficient  pam_unix.so       sha512 shadow nullok try_first_pass use_authtok',
        '/etc/pam.d/password-auth:password  sufficient  pam_unix.so       sha512 shadow nullok try_first_pass use_authtok',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_hashing_algorithm_pass_regression1(*args):
    returncode = 0
    stderr = ['']
    stdout = [
        '/etc/pam.d/system-auth:password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok',
        '/etc/pam.d/password-auth:password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_hashing_algorithm_fail(*args):
    returncode = 1
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_password_hashing_algorithm_pass)
def test_audit_password_hashing_algorithm_pass():
    state = test.audit_password_hashing_algorithm()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_password_hashing_algorithm_pass_regression1)
def test_audit_password_hashing_algorithm_pass_regression1():
    state = test.audit_password_hashing_algorithm()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_password_hashing_algorithm_fail)
def test_audit_password_hashing_algorithm_pass_fail():
    state = test.audit_password_hashing_algorithm()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
