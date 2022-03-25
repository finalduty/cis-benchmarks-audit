#!/usr/bin/env python3

from cis_audit import CISAudit
from unittest.mock import patch
import pytest

test = CISAudit()


def mock_audit_package_not_installed_or_service_is_masked_pass(package, service):
    return 0


def mock_audit_package_not_installed_or_service_is_masked_fail(package, service):
    return 1


@patch.object(CISAudit, "audit_package_not_installed", mock_audit_package_not_installed_or_service_is_masked_pass)
@patch.object(CISAudit, "audit_service_is_masked", mock_audit_package_not_installed_or_service_is_masked_pass)
def test_audit_package_not_installed_or_service_is_masked_pass():
    state = test.audit_package_not_installed_or_service_is_masked(package='pytest', service='pytestd')
    assert state == 0


@patch.object(CISAudit, "audit_package_not_installed", mock_audit_package_not_installed_or_service_is_masked_fail)
@patch.object(CISAudit, "audit_service_is_masked", mock_audit_package_not_installed_or_service_is_masked_fail)
def test_audit_package_not_installed_or_service_is_masked_fail():
    state = test.audit_package_not_installed_or_service_is_masked(package='pytest', service='pytestd')
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
