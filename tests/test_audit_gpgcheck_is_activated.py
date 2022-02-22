#!/usr/bin/env python3

import cis_audit
from unittest.mock import patch
from types import SimpleNamespace


def mock_gpgcheck_activated_pass(cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=1']
        error = ['']
        returncode = 0
    
    elif 'yum.repos.d' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_1(cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=0']
        error = ['']
        returncode = 0
    
    elif 'yum.repos.d' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_2(cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=1']
        error = ['']
        returncode = 0
    
    elif 'yum.repos.d' in cmd:
        output = ['base does not have gpgcheck enabled']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_fail_state_3(cmd):
    if 'yum.conf' in cmd:
        output = ['gpgcheck=0']
        error = ['']
        returncode = 0
    
    elif 'yum.repos.d' in cmd:
        output = ['base does not have gpgcheck enabled.']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_gpgcheck_activated_exception(cmd):
    raise Exception


class TestGPGCheckActivated:
    test = cis_audit.CISAudit()
    test_id = '1.1'

    @patch.object(cis_audit, "shellexec", mock_gpgcheck_activated_pass)
    def test_check_gpgcheck_is_activated_pass(self, caplog):
        result = self.test.audit_gpgcheck_is_activated(self.test_id)

        assert result == 'Pass'
        assert caplog.records[0].msg == f'Test {self.test_id} passed with state 0'

    @patch.object(cis_audit, "shellexec", mock_gpgcheck_activated_fail_state_1)
    def test_check_gpgcheck_is_activated_fail_state_1(self, caplog):
        result = self.test.audit_gpgcheck_is_activated(self.test_id)

        assert result == 'Fail'
        assert caplog.records[0].msg == f'Test {self.test_id} failed with state 1'

    @patch.object(cis_audit, "shellexec", mock_gpgcheck_activated_fail_state_2)
    def test_check_gpgcheck_is_activated_fail_state_2(self, caplog):
        result = self.test.audit_gpgcheck_is_activated(self.test_id)

        assert result == 'Fail'
        assert caplog.records[0].msg == f'Test {self.test_id} failed with state 2'

    @patch.object(cis_audit, "shellexec", mock_gpgcheck_activated_fail_state_3)
    def test_check_gpgcheck_is_activated_fail_state_3(self, caplog):
        result = self.test.audit_gpgcheck_is_activated(self.test_id)

        assert result == 'Fail'
        assert caplog.records[0].msg == f'Test {self.test_id} failed with state 3'

    @patch.object(cis_audit, "shellexec", mock_gpgcheck_activated_exception)
    def test_check_gpgcheck_is_activated_error(self, caplog):
        result = self.test.audit_gpgcheck_is_activated(self.test_id)

        assert result == 'Error'
        assert caplog.records[1].msg == f'Test {self.test_id} errored with state 0'
