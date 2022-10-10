#!/usr/bin/env python3

import pytest
import shutil

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shutil.copy('/etc/login.defs', '/etc/login.defs.bak')
    shutil.copy('/etc/shadow', '/etc/shadow.bak')

    shellexec(R"sed -i 's/^\s*PASS_WARN_AGE.*/PASS_WARN_AGE 0/' /etc/login.defs")
    shellexec("sed -i -E '/(root|vagrant):/ s/0:99999:7/0:99999:0/' /etc/shadow")

    yield None

    ## Tear-down
    shutil.move('/etc/login.defs.bak', '/etc/login.defs')
    shutil.move('/etc/shadow.bak', '/etc/shadow')


def test_integration_audit_password_expiration_warning_is_configured_pass():
    state = CISAudit().audit_password_expiration_warning_is_configured()
    assert state == 0


def test_integration_audit_password_expiration_warning_is_configured_fail(setup_to_fail):
    state = CISAudit().audit_password_expiration_warning_is_configured()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
