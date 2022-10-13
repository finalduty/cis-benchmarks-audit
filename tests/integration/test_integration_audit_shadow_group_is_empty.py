#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_empty():
    ## Setup
    shellexec('groupadd -r shadow')

    yield None

    ## Tear-down
    shellexec('groupdel shadow')


@pytest.fixture
def setup_to_fail_primary():
    ## Setup
    shellexec('groupadd -r shadow')
    shellexec('useradd -g shadow pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('groupdel shadow')


@pytest.fixture
def setup_to_fail_supplementary():
    ## Setup
    shellexec('groupadd -r shadow')
    shellexec('useradd -G shadow pytest')

    yield None

    ## Tear-down
    shellexec('userdel pytest')
    shellexec('groupdel shadow')


def test_integration_audit_shadow_group_is_empty_pass_absent():
    state = CISAudit().audit_shadow_group_is_empty()
    assert state == 0


def test_integration_audit_shadow_group_is_empty_pass_empty(setup_to_pass_empty):
    state = CISAudit().audit_shadow_group_is_empty()
    assert state == 0


def test_integration_audit_shadow_group_is_empty_fail_primary(setup_to_fail_primary):
    state = CISAudit().audit_shadow_group_is_empty()
    assert state == 2


def test_integration_audit_shadow_group_is_empty_fail_supplementary(setup_to_fail_supplementary):
    state = CISAudit().audit_shadow_group_is_empty()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
