#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('systemctl mask rsyncd')

    yield None

    ## Tear-down
    shellexec('systemctl unmask rsyncd')


def test_integration_audit_service_masked_pass(setup_to_pass):
    state = CISAudit().audit_service_is_masked(service='rsyncd')
    assert state == 0


def test_integration_audit_service_masked_fail():
    state = CISAudit().audit_service_is_masked(service='rsyncd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
