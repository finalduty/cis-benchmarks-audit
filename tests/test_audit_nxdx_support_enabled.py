#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nxdx_support_pass(self, cmd):
    stdout = ['[    0.000000] NX (Execute Disable) protection: active']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nxdx_support_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestNXDXSupportEnabled:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_nxdx_support_pass)
    def test_nxdx_support_enabled_pass(self):
        state = self.test.audit_nxdx_support_enabled()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_nxdx_support_fail)
    def test_nxdx_support_enabled_fail(self):
        state = self.test.audit_nxdx_support_enabled()
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
