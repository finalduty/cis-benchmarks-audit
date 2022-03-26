#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_gpgcheck_activated_pass(self, cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=1']
        error = ['']
        returncode = 0

    elif 'yum.repos.d' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_1(self, cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=0']
        error = ['']
        returncode = 0

    elif 'yum.repos.d' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_2(self, cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=1']
        error = ['']
        returncode = 0

    elif 'yum.repos.d' in cmd:
        output = ['base does not have gpgcheck enabled']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_3(self, cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=0']
        error = ['']
        returncode = 0

    elif 'yum.repos.d' in cmd:
        output = ['base does not have gpgcheck enabled.']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestGPGCheckActivated:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_gpgcheck_activated_pass)
    def test_check_gpgcheck_is_activated_pass(self):
        state = self.test.audit_gpgcheck_is_activated()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_gpgcheck_activated_fail_state_1)
    def test_check_gpgcheck_is_activated_fail_state_1(self):
        state = self.test.audit_gpgcheck_is_activated()
        assert state == 1

    @patch.object(CISAudit, "_shellexec", mock_gpgcheck_activated_fail_state_2)
    def test_check_gpgcheck_is_activated_fail_state_2(self):
        state = self.test.audit_gpgcheck_is_activated()
        assert state == 2

    @patch.object(CISAudit, "_shellexec", mock_gpgcheck_activated_fail_state_3)
    def test_check_gpgcheck_is_activated_fail_state_3(self):
        state = self.test.audit_gpgcheck_is_activated()
        assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
