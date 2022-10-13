#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    '''Create a duplicate gid for the purpose of forcing the test to fail'''

    ## Setup
    cmd = 'echo "pytest:x:0:" >> /etc/group'
    shellexec(cmd)

    yield None

    ## Cleanup
    cmd = 'sed -i "/pytest/d" /etc/group'
    shellexec(cmd)


def test_audit_duplicate_gids_pass():
    state = CISAudit().audit_duplicate_gids()
    assert state == 0


def test_audit_duplicate_gids_fail(setup_to_fail):
    state = CISAudit().audit_duplicate_gids()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
