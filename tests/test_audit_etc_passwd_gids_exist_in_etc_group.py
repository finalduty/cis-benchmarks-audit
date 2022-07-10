#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_gids_in_passwd_pass(self, cmd):
    if '/etc/group' in cmd:
        output = ['1000', '1001', '']
    elif '/etc/passwd' in cmd:
        output = ['1000', '1001', '']
    else:
        output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gids_in_passwd_fail(self, cmd):
    if '/etc/group' in cmd:
        output = ['1000', '']
    elif '/etc/passwd' in cmd:
        output = ['1000', '1001', '']
    else:
        output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_gids_in_passwd_pass)
def test_gids_from_etcpasswd_are_in_etcgroup_pass():
    state = test.audit_etc_passwd_gids_exist_in_etc_group()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_gids_in_passwd_fail)
def test_gids_from_etcpasswd_are_in_etcgroup_fail():
    state = test.audit_etc_passwd_gids_exist_in_etc_group()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
