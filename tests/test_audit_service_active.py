#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_active(*args, **kwargs):
    output = ['active']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_stopped(*args, **kwargs):
    output = ['inactive']
    error = ['']
    returncode = 3

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_error(*args, **kwargs):
    output = ['']
    error = ['Failed to get unit file state for pytest.service: No such file or directory']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestService:
    test = CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_active)
    def test_service_active_pass(self):
        state = self.test.audit_service_is_active(service=self.test_service)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_stopped)
    def test_service_active_fail(self):
        state = self.test.audit_service_is_active(service=self.test_service)
        assert state == 1


#    @patch.object(CISAudit, "_shellexec", mock_error)
#    def test_service_active_error(self):
#        state = self.test.audit_service_is_active(service=self.test_service)
#        assert state == -1

if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
