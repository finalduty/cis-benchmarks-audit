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

    with open('/etc/dconf/db/gdm.d/01-banner-message', 'w') as f:
        f.writelines(
            [
                '[org/gnome/login-screen]\n',
                'banner-message-enable=true\n',
                'banner-message-text="<banner message>"\n',
            ]
        )

    yield None

    os.remove('/etc/dconf/profile/gdm')
    os.remove('/etc/dconf/db/gdm.d/01-banner-message')


@pytest.fixture
def setup_to_fail():
    shellexec('touch /etc/dconf/profile/gdm')
    shellexec('touch /etc/dconf/db/gdm.d/01-banner-message')

    yield None

    os.remove('/etc/dconf/profile/gdm')
    os.remove('/etc/dconf/db/gdm.d/01-banner-message')


def test_integration_audit_gdm_login_banner_configured_error_not_installed():
    state = CISAudit().audit_gdm_login_banner_configured()
    assert state == -2


def test_integration_audit_gdm_login_banner_configured_fail_files_not_found(setup_install_gdm):
    state = CISAudit().audit_gdm_login_banner_configured()
    assert state == 17


def test_integration_audit_gdm_login_banner_configured_fail(setup_install_gdm, setup_to_fail):
    state = CISAudit().audit_gdm_login_banner_configured()
    assert state == 46


def test_integration_audit_gdm_login_banner_configured_pass(setup_install_gdm, setup_to_pass):
    state = CISAudit().audit_gdm_login_banner_configured()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
