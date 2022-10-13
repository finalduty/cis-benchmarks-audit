#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    with open('/etc/dconf/profile/gdm', 'w') as f:
        f.writelines(
            [
                'user-db:user\n',
                'system-db:gdm\n',
                'file-db:/usr/share/gdm/greeter-dconf-defaults\n',
            ]
        )

    with open('/etc/dconf/db/gdm.d/00-login-screen', 'w') as f:
        f.writelines(
            [
                '[org/gnome/login-screen]\n',
                'disable-user-list=true\n',
            ]
        )

    yield None

    os.remove('/etc/dconf/profile/gdm')
    os.remove('/etc/dconf/db/gdm.d/00-login-screen')


@pytest.fixture
def setup_to_fail():
    shellexec('touch /etc/dconf/profile/gdm')
    shellexec('touch /etc/dconf/db/gdm.d/00-login-screen')

    yield None

    os.remove('/etc/dconf/profile/gdm')
    os.remove('/etc/dconf/db/gdm.d/00-login-screen')


def test_integration_audit_gdm_last_user_logged_in_disabled_error_not_installed():
    state = CISAudit().audit_gdm_last_user_logged_in_disabled()
    assert state == -2


def test_integration_audit_gdm_last_user_logged_in_disabled_fail_files_not_found(setup_install_gdm):
    state = CISAudit().audit_gdm_last_user_logged_in_disabled()
    assert state == 17


def test_integration_audit_gdm_last_user_logged_in_disabled_fail(setup_install_gdm, setup_to_fail):
    state = CISAudit().audit_gdm_last_user_logged_in_disabled()
    assert state == 46


def test_integration_audit_gdm_last_user_logged_in_disabled_pass(setup_install_gdm, setup_to_pass):
    state = CISAudit().audit_gdm_last_user_logged_in_disabled()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
