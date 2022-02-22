#!/usr/bin/env python3

import cis_audit
from types import SimpleNamespace
from unittest.mock import patch


def mock_disabled(cmd):
    output = ['disabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_enabled(cmd):
    output = ['enabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_error(cmd):
    output = ['']
    error = ['Failed to get unit file state for pytest.service: No such file or directory']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestService:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(cis_audit, "shellexec", mock_disabled)
    def test_service_disabled(self, caplog):
        result = self.test.audit_service_is_enabled(self.test_id, service=self.test_service)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_enabled)
    def test_service_enabled(self, caplog):
        result = self.test.audit_service_is_enabled(self.test_id, service=self.test_service)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_error)
    def test_service_error(self, caplog):
        result = self.test.audit_service_is_enabled(self.test_id, service=self.test_service)

        assert result == 'Error'
