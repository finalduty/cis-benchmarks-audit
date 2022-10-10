#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('chown -c root.root /etc/ssh/ssh_host_*_key')
    shellexec('chmod -c 600 /etc/ssh/ssh_host_*_key')

    yield None

    shellexec('chown -c root.ssh_keys /etc/ssh/ssh_host_*_key')
    shellexec('chmod -c 640 /etc/ssh/ssh_host_*_key')


def test_integration_audit_permissions_on_private_host_key_files_pass(setup_to_pass):
    state = CISAudit().audit_permissions_on_private_host_key_files()
    assert state == 0


def test_integration_audit_permissions_on_private_host_key_files_fail():
    state = CISAudit().audit_permissions_on_private_host_key_files()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
