#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('nft add rule inet filter input iif lo accept')
    shellexec('nft add rule inet filter input ip saddr 127.0.0.0/8 counter drop')
    shellexec('nft add rule inet filter input ip6 saddr ::1/128 counter drop')

    yield None

    ## Tear-down
    shellexec('nft flush chain inet filter input')


def test_integration_audit_nftables_loopback_is_configured_pass(setup_install_nftables, setup_to_pass):
    state = CISAudit().audit_nftables_loopback_is_configured()
    assert state == 0


def test_integration_audit_nftables_loopback_is_configured_fail(setup_install_nftables):
    state = CISAudit().audit_nftables_loopback_is_configured()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
