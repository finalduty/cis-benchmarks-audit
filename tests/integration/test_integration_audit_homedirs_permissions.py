#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture(params=[750, 700])
def setup_to_pass(request):
    ## Setup
    shellexec('useradd pytest')
    shellexec(f'chmod {request.param} /home/pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('rm -rf /home/pytest')


@pytest.fixture(params=[755, 770])
def setup_to_fail(request):
    ## Setup
    shellexec('useradd pytest')
    shellexec(f'chmod {request.param} /home/pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('rm -rf /home/pytest')


def test_integration_audit_homedirs_permissions_pass(setup_to_pass):
    state = CISAudit().audit_homedirs_permissions()
    assert state == 0


def test_integration_audit_homedirs_permissions_fail(setup_to_fail):
    state = CISAudit().audit_homedirs_permissions()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
