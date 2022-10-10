#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    print(shellexec('pkill -e VBoxService'))

    yield None

    print('systemctl restart vboxadd-service')


@pytest.fixture
def setup_to_fail():
    ## Setup
    ## https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/sect-security-enhanced_linux-targeted_policy-unconfined_processes
    shellexec('chcon -t bin_t /usr/bin/rsync')
    shellexec('systemctl start rsyncd')

    yield None

    ## Tear-down
    shellexec('systemctl stop rsyncd')
    shellexec('restorecon -v /usr/bin/rsync')


def test_integration_audit_no_unconfined_services_pass(setup_to_pass):
    state = CISAudit().audit_no_unconfined_services()
    assert state == 0


def test_integration_audit_no_unconfined_services_fail(setup_to_fail):
    state = CISAudit().audit_no_unconfined_services()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
