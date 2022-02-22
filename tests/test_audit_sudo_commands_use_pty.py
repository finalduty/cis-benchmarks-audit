#!/usr/bin/env python3

from types import SimpleNamespace
import cis_audit
from unittest.mock import patch


def mock_sudo_use_pty_pass(*args, **kwargs):
    output = ['Defaults use_pty']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sudo_use_pty_fail(*args, **kwargs):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sudo_use_pty_error(*args, **kwargs):
    raise Exception


class TestSudoCommandUsePty:
    test = cis_audit.CISAudit()
    test_id = '1.1'

    @patch.object(cis_audit, "shellexec", mock_sudo_use_pty_pass)
    def test_sudo_use_pty_pass(self):
        result = self.test.audit_sudo_commands_use_pty(self.test_id)

        assert result == 'Pass'


    @patch.object(cis_audit, "shellexec", mock_sudo_use_pty_fail)
    def test_sudo_use_pty_fail(self):
        result = self.test.audit_sudo_commands_use_pty(self.test_id)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_sudo_use_pty_error)
    def test_sudo_use_pty_error(self):
        result = self.test.audit_sudo_commands_use_pty(self.test_id)

        assert result == 'Error'
