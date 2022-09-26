#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('echo "pytest:x:1001:" >> /etc/group')
    shellexec('echo "pytest:x:1002:" >> /etc/group')

    yield None

    shellexec('sed -i "/pytest/d" /etc/group')


def test_audit_integration_duplicate_group_names_pass():
    state = CISAudit().audit_duplicate_group_names()
    assert state == 0


def test_audit_integration_duplicate_group_names_fail(setup_to_fail):
    state = CISAudit().audit_duplicate_group_names()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
