#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit


def test_integration_audit_only_one_package_is_installed_pass():
    state = CISAudit().audit_only_one_package_is_installed(packages="rsync gdm")
    assert state == 0


def test_integration_audit_only_one_package_is_installed_fail_both_installed():
    state = CISAudit().audit_only_one_package_is_installed(packages='rsync bash')
    assert state == 1


def test_integration_audit_only_one_package_is_installed_fail_neither_installed():
    state = CISAudit().audit_only_one_package_is_installed(packages="java-1.8.0-openjdk java-11-openjdk")
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
