#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('systemctl start firewalld')

    yield None

    ## Tear-down
    shellexec('systemctl stop firewalld')


def test_integration_firewalld_defaullt_zone_set_pass(setup_to_pass):
    state = CISAudit().audit_firewalld_default_zone_is_set()
    assert state == 0


def test_integration_firewalld_not_running():
    state = CISAudit().audit_firewalld_default_zone_is_set()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
