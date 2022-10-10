#!/usr/bin/env python3

import pytest
import shutil
import os

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture(params=['minimum', 'mls'])
def setup_to_fail(request):
    ## Setup
    shutil.copy('/etc/selinux/config', '/etc/selinux/config.bak')
    shellexec(Rf"sed -i '/SELINUXTYPE=/ s/=.*$/{request.param}/' /etc/selinux/config")

    with open('/usr/local/sbin/sestatus', 'w') as f:
        f.write(f'echo Loaded policy name:             {request.param}')
    shellexec('chmod +x /usr/local/sbin/sestatus')

    yield None

    ## Tear-down
    shutil.move('/etc/selinux/config.bak', '/etc/selinux/config')
    os.remove('/usr/local/sbin/sestatus')


def test_integration_audit_selinux_policy_configured_pass():
    state = CISAudit().audit_selinux_policy_is_configured()
    assert state == 0


def test_integration_audit_selinux_policy_configured_fail(setup_to_fail):
    state = CISAudit().audit_selinux_policy_is_configured()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
