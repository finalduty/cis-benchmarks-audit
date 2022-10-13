#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec(r'nft create table inet filter')
    shellexec(r'nft create chain inet filter input { type filter hook input priority 0 \; }')
    shellexec(r'nft create chain inet filter forward { type filter hook forward priority 0 \; }')
    shellexec(r'nft create chain inet filter output { type filter hook output priority 0 \; }')

    yield None

    shellexec('nft delete table inet filter')


@pytest.fixture
def setup_to_fail():
    shellexec('nft flush chain inet filter input')
    shellexec('nft flush chain inet filter forward')
    shellexec('nft flush chain inet filter output')

    shellexec('nft delete chain inet filter input')
    shellexec('nft delete chain inet filter forward')
    shellexec('nft delete chain inet filter output')

    print(shellexec('nft list ruleset'))

    yield None

    shellexec(r'nft create chain inet filter input { type filter hook input priority 0 \; }')
    shellexec(r'nft create chain inet filter forward { type filter hook forward priority 0 \; }')
    shellexec(r'nft create chain inet filter output { type filter hook output priority 0 \; }')


def test_integration_audit_nftables_base_chains_exist_pass(setup_install_nftables):
    state = CISAudit().audit_nftables_base_chains_exist()
    assert state == 0


def test_integration_audit_nftables_base_chains_exist_fail(setup_install_nftables, setup_to_fail):
    state = CISAudit().audit_nftables_base_chains_exist()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
