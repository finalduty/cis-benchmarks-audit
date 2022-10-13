#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec('nft add rule inet filter input dport tcp ssh accept')
    shellexec('nft add rule inet filter input ct state established accept')
    shellexec('nft add rule inet filter output ct state new,related,established accept')

    shellexec(R'nft chain inet filter input { policy drop \; }')
    shellexec(R'nft chain inet filter forward { policy drop \; }')
    shellexec(R'nft chain inet filter output { policy drop \; }')

    yield None

    shellexec(R'nft chain inet filter input { policy accept \; }')
    shellexec(R'nft chain inet filter forward { policy accept \; }')
    shellexec(R'nft chain inet filter output { policy accept \; }')

    shellexec('nft flush chain inet filter input')
    shellexec('nft flush chain inet filter forward')
    shellexec('nft flush chain inet filter output')


def test_integration_audit_nftables_default_deny_policy_pass(setup_install_nftables, setup_to_pass):
    state = CISAudit().audit_nftables_default_deny_policy()
    assert state == 0


def test_integration_audit_nftables_default_deny_policy_fail(setup_install_nftables):
    state = CISAudit().audit_nftables_default_deny_policy()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
