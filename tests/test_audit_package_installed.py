#!/usr/bin/env python3

import cis_audit
from unittest.mock import patch
from types import SimpleNamespace


def mock_package_installed(*args):
    output = ['pytest-0.0.0\n']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_package_not_installed(cmd):
    output = ['package pytest is not installed\n']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_package_error(cmd):
    output = ['']
    error = {'rpm: no arguments given for query\n'}
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPackageInstalled:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_package = 'pytest'
    
    @patch.object(cis_audit, "shellexec", mock_package_installed)
    def test_package_is_installed_pass(self):
        result = self.test.audit_package_is_installed(self.test_id, package=self.test_package)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_package_not_installed)
    def test_package_is_installed_fail(self):
        result = self.test.audit_package_is_installed(self.test_id, package=self.test_package)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_package_error)
    def test_package_is_installed_error(self):
        result = self.test.audit_package_is_installed(self.test_id, package=self.test_package)

        assert result == 'Error'


class TestPackageNotInstalled:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_package = 'pytest'

    @patch.object(cis_audit, "shellexec", mock_package_installed)
    def test_package_is_not_installed_pass(self):
        result = self.test.audit_package_is_not_installed(self.test_id, package=self.test_package)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_package_not_installed)
    def test_package_is_not_installed_fail(self):
        result = self.test.audit_package_is_not_installed(self.test_id, package=self.test_package)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_package_error)
    def test_package_is_not_installed_error(self):
        result = self.test.audit_package_is_not_installed(self.test_id, package=self.test_package)

        assert result == 'Error'
