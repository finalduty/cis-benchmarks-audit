#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('usermod -g 1 root')

    yield None

    shellexec('usermod -g 0 root')


def test_integration_audit_default_group_for_root_pass():
    state = CISAudit().audit_default_group_for_root()
    assert state == 0


def test_integration_audit_default_group_for_root_fail(setup_to_fail):
    state = CISAudit().audit_default_group_for_root()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
