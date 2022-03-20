#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_xdcmp_not_enabled_pass(*args, **kwargs):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_xdcmp_not_enabled_fail(*args, **kwargs):
    stdout = ['Enabled=true']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestXDCMPNotEnabled:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_xdcmp_not_enabled_pass)
    def test_audit_xdcmp_not_enabled_pass(self):
        state = self.test.audit_xdcmp_not_enabled()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_xdcmp_not_enabled_fail)
    def test_audit_xdcmp_not_enabled_fail(self):
        state = self.test.audit_xdcmp_not_enabled()
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
