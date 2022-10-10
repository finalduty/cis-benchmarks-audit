#!/usr/bin/env python3

import os
import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('find /var/log -type f -exec chmod g-wx,o-rwx "{}" +')

    yield None


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec('touch /var/log/pytest')

    yield None

    ## Tear-down
    os.remove('/var/log/pytest')


def test_integration_audit_permissions_on_log_files_are_configured_pass(setup_to_pass):
    state = CISAudit().audit_permissions_on_log_files()
    assert state == 0


def test_integration_audit_permissions_on_log_files_are_configured_fail(setup_to_fail):
    state = CISAudit().audit_permissions_on_log_files()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
