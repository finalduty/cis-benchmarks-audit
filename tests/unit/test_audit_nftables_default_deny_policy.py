#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nftables_default_deny_policy_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = ['type filter hook input priority 0; policy drop;']
    elif 'forward' in cmd:
        stdout = ['type filter hook forward priority 0; policy drop;']
    elif 'output' in cmd:
        stdout = ['type filter hook output priority 0; policy drop;']
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_default_deny_policy_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_nftables_default_deny_policy_pass)
def test_audit_nftables_default_deny_policy_pass():
    state = CISAudit().audit_nftables_default_deny_policy()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_nftables_default_deny_policy_fail)
def test_audit_nftables_default_deny_policy_fail():
    state = CISAudit().audit_nftables_default_deny_policy()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
