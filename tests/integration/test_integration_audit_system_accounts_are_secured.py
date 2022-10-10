#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('useradd -r -s /bin/bash pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')


def test_integration_audit_system_accounts_are_secured_pass():
    state = CISAudit().audit_system_accounts_are_secured()
    assert state == 0


def test_integration_audit_system_accounts_are_secured_fail(setup_to_fail):
    state = CISAudit().audit_system_accounts_are_secured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
