#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_package_installed(*args):
    output = ['pytest-0.0.0', '']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_package_not_installed(self, cmd):
    output = ['package pytest is not installed', '']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPackageNotInstalled:
    test = CISAudit()
    test_id = '1.1'
    test_package = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_package_not_installed)
    def test_package_not_installed_pass(self):
        state = self.test.audit_package_not_installed(package=self.test_package)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_package_installed)
    def test_package_not_installed_fail(self):
        state = self.test.audit_package_not_installed(package=self.test_package)
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
