#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_command_pass(*args, **kwargs):
    stdout = ['ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_command_fail(*args, **kwargs):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestAuthForSingleUserMode:
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_command_pass)
    def test_auth_for_single_user_pass(self):
        state = self.test.audit_auth_for_single_user_mode()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_command_fail)
    def test_auth_for_single_user_fail(self):
        state = self.test.audit_auth_for_single_user_mode()
        assert state == 3


if __name__ == '__main__':
    pytest.main([__file__])
