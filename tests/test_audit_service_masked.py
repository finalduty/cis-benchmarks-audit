#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_masked(*args, **kwargs):
    output = ['masked']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_unmasked(*args, **kwargs):
    output = ['enabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_error(*args, **kwargs):
    output = ['']
    error = ['Failed to get unit file state for pytest.service: No such file or directory']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestServiceMasked:
    test = CISAudit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_masked)
    def test_service_masked_pass(self):
        state = self.test.audit_service_is_masked(service=self.test_service)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_unmasked)
    def test_service_masked_fail(self):
        state = self.test.audit_service_is_masked(service=self.test_service)
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
