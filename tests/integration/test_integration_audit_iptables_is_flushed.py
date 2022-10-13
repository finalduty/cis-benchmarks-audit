#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('iptables -A INPUT -i lo -j ACCEPT')
    shellexec('ip6tables -A INPUT -i lo -j ACCEPT')

    yield None

    ## Tear-down
    shellexec('iptables -F')
    shellexec('ip6tables -F')


def test_integration_iptables_is_flushed_pass():
    state = CISAudit().audit_iptables_is_flushed()
    assert state == 0


def test_integration_iptables_is_flushed_fail(setup_to_fail):
    state = CISAudit().audit_iptables_is_flushed()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
