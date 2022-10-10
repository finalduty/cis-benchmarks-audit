#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec('nft add rule inet filter input ip protocol tcp ct state established accept')
    shellexec('nft add rule inet filter input ip protocol udp ct state established accept')
    shellexec('nft add rule inet filter input ip protocol icmp ct state established accept')
    shellexec('nft add rule inet filter output ip protocol tcp ct state new,related,established accept')
    shellexec('nft add rule inet filter output ip protocol udp ct state new,related,established accept')
    shellexec('nft add rule inet filter output ip protocol icmp ct state new,related,established accept')

    yield None

    shellexec('nft flush chain inet filter input')
    shellexec('nft flush chain inet filter forward')
    shellexec('nft flush chain inet filter output')


def test_integration_audit_nftables_outbound_and_established_connections_pass(setup_install_nftables, setup_to_pass):
    state = CISAudit().audit_nftables_outbound_and_established_connections()
    assert state == 0


def test_integration_audit_nftables_outbound_and_established_connections_fail(setup_install_nftables):
    state = CISAudit().audit_nftables_outbound_and_established_connections()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
