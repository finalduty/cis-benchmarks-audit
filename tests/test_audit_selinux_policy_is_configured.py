#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_selinux_policy_configured_pass(self, cmd):
    stdout = ['targeted']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_selinux_policy_configured_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestSELinuxPolicyConfigured:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_selinux_policy_configured_pass)
    def test_selinux_policy_configured_pass(self):
        state = self.test.audit_selinux_policy_is_configured()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_selinux_policy_configured_fail)
    def test_selinux_policy_configured_fail(self):
        state = self.test.audit_selinux_policy_is_configured()
        assert state == 3

if __name__ == '__main__':
    pytest.main([__file__])
