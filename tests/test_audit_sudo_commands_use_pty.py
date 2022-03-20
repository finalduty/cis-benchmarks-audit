#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


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
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_sudo_use_pty_pass)
    def test_sudo_use_pty_pass(self):
        state = self.test.audit_sudo_commands_use_pty()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_sudo_use_pty_fail)
    def test_sudo_use_pty_fail(self):
        state = self.test.audit_sudo_commands_use_pty()
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
