#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_updates_pass(*args, **kwargs):
    stdout = []
    stderr = []
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_updates_fail(*args, **kwargs):
    stdout = [
        'kernel.x86_64                        3.10.0-1160.59.1.el7                updates',
        'kernel-tools.x86_64                  3.10.0-1160.59.1.el7                updates',
        'kernel-tools-libs.x86_64             3.10.0-1160.59.1.el7                updates',
    ]
    stderr = []
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestUpdatesInstalled:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_updates_pass)
    def test_updates_installed_pass(self):
        state = self.test.audit_updates_installed()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_updates_fail)
    def test_updates_installed_fail(self):
        state = self.test.audit_updates_installed()
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
