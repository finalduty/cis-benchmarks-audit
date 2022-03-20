#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_selinux_mode_is_enforcing_enforcing(self, cmd):
    stdout = ['enforcing']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_selinux_mode_is_enforcing_permissive(self, cmd):
    stdout = ['permissive']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_selinux_mode_is_enforcing_disabled(self, cmd):
    stdout = ['disabled']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestSELinuxIsEnforcing:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_selinux_mode_is_enforcing_enforcing)
    def test_selinux_is_enforcing_enforcing_pass(self):
        state = self.test.audit_selinux_mode_is_enforcing()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_selinux_mode_is_enforcing_permissive)
    def test_selinux_is_enforcing_permissive_pass(self):
        state = self.test.audit_selinux_mode_is_enforcing()
        assert state == 3

    @patch.object(CISAudit, "_shellexec", mock_selinux_mode_is_enforcing_disabled)
    def test_selinux_is_enforcing_disabled_fail(self):
        state = self.test.audit_selinux_mode_is_enforcing()
        assert state == 3

if __name__ == '__main__':
    pytest.main([__file__])
