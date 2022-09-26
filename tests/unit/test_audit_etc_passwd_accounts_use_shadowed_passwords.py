#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_etc_passwd_accounts_use_shadowed_passwords_pass(self, cmd):
    returncode = 1
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_etc_passwd_accounts_use_shadowed_passwords_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['pytest:!!:1000:1000::/home/pytest:/bin/bash']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_etc_passwd_accounts_use_shadowed_passwords_pass)
def test_audit_etc_passwd_accounts_use_shadowed_passwords_pass():
    state = test.audit_etc_passwd_accounts_use_shadowed_passwords()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_etc_passwd_accounts_use_shadowed_passwords_fail)
def test_audit_etc_passwd_accounts_use_shadowed_passwords_fail():
    state = test.audit_etc_passwd_accounts_use_shadowed_passwords()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
