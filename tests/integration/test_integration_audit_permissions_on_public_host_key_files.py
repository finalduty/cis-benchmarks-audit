#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('chmod -c 664 /etc/ssh/ssh_host_*_key.pub')

    yield None

    shellexec('chmod -c 644 /etc/ssh/ssh_host_*_key.pub')


def test_integration_audit_permissions_on_public_host_key_files_pass():
    state = CISAudit().audit_permissions_on_public_host_key_files()
    assert state == 0


def test_integration_audit_permissions_on_public_host_key_files_fail(setup_to_fail):
    state = CISAudit().audit_permissions_on_public_host_key_files()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
