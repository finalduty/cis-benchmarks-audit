#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('useradd --no-create-home pytest')
    shellexec('rm -rf /home/pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('useradd pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')


def test_integration_audit_homedirs_exist_fail(setup_to_fail):
    state = CISAudit().audit_homedirs_exist()
    assert state == 1


def test_integration_audit_homedirs_exist_pass():
    state = CISAudit().audit_homedirs_exist()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
