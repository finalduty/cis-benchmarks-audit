#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from unittest.mock import patch
from types import SimpleNamespace

test = CISAudit()


def mock_password_expiration_max_days_is_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'PASS_MAX_DAYS' in cmd:
        stdout = ['PASS_MAX_DAYS    365']
    elif 'shadow' in cmd:
        stdout = [
            'root:365',
            'vagrant:365',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_expiration_max_days_is_configured_fail(self, cmd):
    returncode = 0
    stderr = ['']

    if 'PASS_MAX_DAYS' in cmd:
        stdout = ['PASS_MAX_DAYS    99999']
    elif 'shadow' in cmd:
        stdout = [
            'root:99999',
            'vagrant:99999',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_password_expiration_max_days_is_configured_pass)
def test_audit_password_expiration_max_days_is_configured_pass():
    state = test.audit_password_expiration_max_days_is_configured()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_password_expiration_max_days_is_configured_fail)
def test_audit_password_expiration_max_days_is_configured_pass_fail():
    state = test.audit_password_expiration_max_days_is_configured()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
