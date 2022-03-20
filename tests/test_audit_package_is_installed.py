#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_package_installed(*args):
    output = ['pytest-0.0.0\n']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_package_not_installed(self, cmd):
    output = ['package pytest is not installed\n']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_package_error(self, cmd):
    output = ['']
    error = {'rpm: no arguments given for query\n'}
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_package_installed)
def test_packages_are_installed_pass():
    state = test.audit_package_is_installed(packages=['pytest'])
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_package_not_installed)
def test_packages_are_installed_fail():
    state = test.audit_package_is_installed(packages=['pytest'])
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_package_not_installed)
def test_packages_are_installed_fail_multiple():
    state = test.audit_package_is_installed(packages=['pytest', 'pytest2'])
    assert state == 3


@patch.object(CISAudit, "_shellexec", mock_package_error)
def test_packages_are_installed_error():
    state = test.audit_package_is_installed(packages=['pytest'])
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
