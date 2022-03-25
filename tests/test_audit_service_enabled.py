#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_disabled(*args, **kwargs):
    output = ['disabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_enabled(*args, **kwargs):
    output = ['enabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestService:
    test = CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_enabled)
    def test_service_enabled_pass(self):
        state = self.test.audit_service_is_enabled(service=self.test_service)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_disabled)
    def test_service_enabled_fail(self):
        state = self.test.audit_service_is_enabled(service=self.test_service)
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
