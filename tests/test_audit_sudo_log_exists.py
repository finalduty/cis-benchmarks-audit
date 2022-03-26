#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_sudo_log_exists_pass(*args, **kwargs):
    output = ['Defaults logfile="/var/log/sudo.log"']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sudo_log_exists_fail(*args, **kwargs):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestSudoCommandUsePty:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_sudo_log_exists_pass)
    def test_sudo_log_exists_pass(self):
        state = self.test.audit_sudo_log_exists()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_sudo_log_exists_fail)
    def test_sudo_log_exists_fail(self):
        state = self.test.audit_sudo_log_exists()
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
