#!/usr/bin/env python3

from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_result_pass(package, service):
    return 0


def mock_result_fail(package, service):
    return 1


@patch.object(CISAudit, "audit_package_is_installed", mock_result_fail)
@patch.object(CISAudit, "audit_service_is_masked", mock_result_fail)
def test_audit_package_not_installed_or_service_is_masked_pass_not_installed():
    state = test.audit_package_not_installed_or_service_is_masked(package='pytest', service='pytestd')
    assert state == 0


@patch.object(CISAudit, "audit_package_is_installed", mock_result_pass)
@patch.object(CISAudit, "audit_service_is_masked", mock_result_pass)
def test_audit_package_not_installed_or_service_is_masked_pass_masked():
    state = test.audit_package_not_installed_or_service_is_masked(package='pytest', service='pytestd')
    assert state == 0


@patch.object(CISAudit, "audit_package_is_installed", mock_result_pass)
@patch.object(CISAudit, "audit_service_is_masked", mock_result_fail)
def test_audit_package_not_installed_or_service_is_masked_fail():
    state = test.audit_package_not_installed_or_service_is_masked(package='pytest', service='pytestd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
