#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('useradd pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('rm -rf /home/pytest')


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('useradd pytest')
    shellexec('chown root. /home/pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('rm -rf /home/pytest')


def test_integration_audit_homedirs_ownership_fail(setup_to_fail):
    state = CISAudit().audit_homedirs_ownership()
    assert state == 1


def test_integration_audit_homedirs_ownership_pass(setup_to_pass):
    state = CISAudit().audit_homedirs_ownership()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
