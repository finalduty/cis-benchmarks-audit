#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_disabled_and_inactive(self, cmd, **kwargs):
    if 'is-active' in cmd:
        output = ['inactive']
    elif 'is-enabled' in cmd:
        output = ['disabled']

    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_enabled_and_active(self, cmd, **kwargs):
    if 'is-active' in cmd:
        output = ['active']
    elif 'is-enabled' in cmd:
        output = ['enabled']

    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestService:
    test = CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_enabled_and_active)
    def test_service_is_enabled_and_is_active_pass(self):
        state = self.test.audit_service_is_enabled_and_is_active(service=self.test_service)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_disabled_and_inactive)
    def test_service_is_enabled_and_is_active_fail(self):
        state = self.test.audit_service_is_enabled_and_is_active(service=self.test_service)
        assert state == 3


if __name__ == '__main__':
    pytest.main([__file__])
