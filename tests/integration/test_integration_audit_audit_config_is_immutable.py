#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    ## Setup
    shellexec('echo "-e 2" > /etc/audit/rules.d/99-finalize.rules')

    yield None

    ## Cleanup
    shellexec('rm /etc/audit/rules.d/99-finalize.rules')


@pytest.fixture()
def setup_to_fail():
    shellexec('rm /etc/audit/rules.d/99-finalize.rules')


def test_audit_audit_config_is_immutable_pass(setup_to_pass):
    state = CISAudit().audit_audit_config_is_immutable()
    assert state == 0


def test_audit_audit_config_is_immutable_fail(setup_to_fail):
    state = CISAudit().audit_audit_config_is_immutable()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
