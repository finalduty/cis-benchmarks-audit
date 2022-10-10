#!/usr/bin/env python3

import pytest
import shutil

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture(scope='module')
def setup_sshd_config():
    ## Setup
    shutil.copy('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.bak')
    shellexec("sed -i '/MaxAuthTries/ s/^#//' /etc/ssh/sshd_config")

    yield None

    ## Tear-down
    shutil.move('/etc/ssh/sshd_config.bak', '/etc/ssh/sshd_config')


def test_integration_audit_sshd_config_option_pass_x11forwarding_yes():
    state = CISAudit().audit_sshd_config_option(parameter='x11forwarding', expected_value='yes')
    assert state == 0


def test_integration_audit_sshd_config_option_fail_x11forwarding_no():
    state = CISAudit().audit_sshd_config_option(parameter='x11forwarding', expected_value='no')
    assert state == 2


maxauthtries_pass_params = [
    ## comparison, expected_value
    ('eq', '6'),
    ('le', '6'),
    ('le', '7'),
    ('lt', '7'),
    ('ge', '5'),
    ('ge', '6'),
    ('gt', '5'),
    ('ne', '5'),
]
maxauthtries_fail_params = [
    ## comparison, expected_value
    ('eq', '5'),
    ('le', '4'),
    ('lt', '4'),
    ('ge', '7'),
    ('gt', '7'),
    ('ne', '6'),
]


@pytest.mark.parametrize("comparison, expected_value", maxauthtries_pass_params)
def test_integration_audit_sshd_config_option_pass_maxauthtries(setup_sshd_config, expected_value, comparison):
    state = CISAudit().audit_sshd_config_option(parameter="maxauthtries", expected_value=expected_value, comparison=comparison)
    assert state == 0


@pytest.mark.parametrize("comparison, expected_value", maxauthtries_fail_params)
def test_integration_audit_sshd_config_option_fail_maxauthtries(setup_sshd_config, expected_value, comparison):
    state = CISAudit().audit_sshd_config_option(parameter="maxauthtries", expected_value=expected_value, comparison=comparison)
    assert state == 2


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
