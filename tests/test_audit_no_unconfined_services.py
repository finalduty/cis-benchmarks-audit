#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_unconfined_services_pass(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_unconfined_services_fail(self, cmd):
    stdout = ['system_u:system_r:unconfined_service_t:s0 720 ? 00:03:07 VBoxService']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestUnconfinedServices:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_unconfined_services_pass)
    def test_no_unconfined_services_pass(self):
        state = self.test.audit_no_unconfined_services()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_unconfined_services_fail)
    def test_no_unconfined_services_fail(self):
        state = self.test.audit_no_unconfined_services()
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
