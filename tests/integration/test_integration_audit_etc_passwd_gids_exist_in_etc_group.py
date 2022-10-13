#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('echo "pytest:x:1001:1001::/home/pytest:/bin/bash" >> /etc/passwd')

    yield None

    shellexec('sed -i "/pytest/d" /etc/passwd')


def test_integration_gids_from_etcpasswd_are_in_etcgroup_pass():
    state = CISAudit().audit_etc_passwd_gids_exist_in_etc_group()
    assert state == 0


def test_integration_gids_from_etcpasswd_are_in_etcgroup_fail(setup_to_fail):
    state = CISAudit().audit_etc_passwd_gids_exist_in_etc_group()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
