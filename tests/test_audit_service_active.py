#!/usr/bin/env python3

import cis_audit
from types import SimpleNamespace
from unittest.mock import patch


def mock_stopped(cmd):
    output = ['inactive']
    error = ['']
    returncode = 3

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_active(cmd):
    output = ['active']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_error(cmd):
    raise Exception


class TestService:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(cis_audit, "shellexec", mock_stopped)
    def test_service_stopped(self, caplog):
        result = self.test.audit_service_is_active(self.test_id, service=self.test_service)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_active)
    def test_service_active(self, caplog):
        result = self.test.audit_service_is_active(self.test_id, service=self.test_service)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_error)
    def test_service_error(self, caplog):
        result = self.test.audit_service_is_active(self.test_id, service=self.test_service)

        assert result == 'Error'
