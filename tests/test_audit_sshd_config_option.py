#!/usr/bin/env python3
## https://docs.pytest.org/en/latest/example/parametrize.html

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_sshd_x11forwarding_pass(*args):
    returncode = 0
    stderr = ['']
    stdout = ['x11forwarding no']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_sshd_x11forwarding_fail(*args):
    returncode = 1
    stderr = ['']
    stdout = ['x11forwarding yes']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_sshd_maxauthtries_pass(*args):
    returncode = 0
    stderr = ['']
    stdout = ['maxauthtries 4']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_sshd_maxauthtries_fail(*args):
    returncode = 1
    stderr = ['']
    stdout = ['maxauthtries 5']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_x11forwarding_pass)
def test_audit_sshd_parameter_x11forwarding_pass():
    state = test.audit_sshd_config_option(parameter='x11forwarding', expected_value='no')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_x11forwarding_fail)
def test_audit_sshd_parameter_x11forwarding_fail():
    state = test.audit_sshd_config_option(parameter='x11forwarding', expected_value='no')
    assert state == 3


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_maxauthtries_pass)
def test_audit_sshd_parameter_le_pass():
    state = test.audit_sshd_config_option(parameter="maxauthtries", expected_value="4", comparison="le")
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_maxauthtries_fail)
def test_audit_sshd_parameter_le_fail():
    state = test.audit_sshd_config_option(parameter="maxauthtries", expected_value="4", comparison="le")
    assert state == 3


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_maxauthtries_fail)
def test_audit_sshd_parameter_lt_fail():
    state = test.audit_sshd_config_option(parameter="maxauthtries", expected_value="4", comparison="lt")
    assert state == 3


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_maxauthtries_fail)
def test_audit_sshd_parameter_ge_fail():
    state = test.audit_sshd_config_option(parameter="maxauthtries", expected_value="6", comparison="ge")
    assert state == 3


@patch.object(CISAudit, "_shellexec", mock_audit_sshd_maxauthtries_fail)
def test_audit_sshd_parameter_te_fail():
    state = test.audit_sshd_config_option(parameter="maxauthtries", expected_value="6", comparison="gt")
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__])
