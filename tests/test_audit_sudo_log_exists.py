#!/usr/bin/env python3

from types import SimpleNamespace
import cis_audit
from unittest.mock import patch


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


def mock_sudo_log_exists_error(*args, **kwargs):
    raise Exception


class TestSudoCommandUsePty:
    test = cis_audit.CISAudit()
    test_id = '1.1'

    @patch.object(cis_audit, "shellexec", mock_sudo_log_exists_pass)
    def test_sudo_log_exists_pass(self):
        result = self.test.audit_sudo_log_exists(self.test_id)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_sudo_log_exists_fail)
    def test_sudo_log_exists_fail(self):
        result = self.test.audit_sudo_log_exists(self.test_id)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_sudo_log_exists_error)
    def test_sudo_log_exists_error(self):
        result = self.test.audit_sudo_log_exists(self.test_id)

        assert result == 'Error'
