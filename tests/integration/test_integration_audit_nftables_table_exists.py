#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('nft delete table inet filter')

    yield None

    ## Tear-down
    shellexec('nft create table inet filter')


def test_integration_audit_nftables_table_exists_pass(setup_install_nftables):
    state = CISAudit().audit_nftables_table_exists()
    assert state == 0


def test_integration_audit_nftables_table_exists_fail(setup_install_nftables, setup_to_fail):
    state = CISAudit().audit_nftables_table_exists()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
