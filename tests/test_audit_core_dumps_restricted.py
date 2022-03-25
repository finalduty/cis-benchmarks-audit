#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_core_dumps_pass(self, cmd):
    if 'limits.conf' in cmd:
        stdout = ['* hard core 0']
        stderr = ['']
        returncode = 0
    elif 'sysctl' in cmd:
        stdout = ['fs.suid_dumpable = 0']
        stderr = ['']
        returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_core_dumps_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestCoreDumpsRestricted:
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_core_dumps_pass)
    def test_mock_core_dumps_pass(self):
        state = self.test.audit_core_dumps_restricted()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_core_dumps_fail)
    def test_mock_core_dumps_fail(self):
        state = self.test.audit_core_dumps_restricted()
        assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
