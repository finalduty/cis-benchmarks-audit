#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec('yum update -y')

    yield None


@pytest.fixture
def setup_to_fail():
    shellexec('yum downgrade -y linux-firmware')

    yield None


def test_integration_audit_updates_installed_pass(setup_to_pass):
    state = CISAudit().audit_updates_installed()
    assert state == 0


def test_integration_audit_updates_installed_fail(setup_to_fail):
    state = CISAudit().audit_updates_installed()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
