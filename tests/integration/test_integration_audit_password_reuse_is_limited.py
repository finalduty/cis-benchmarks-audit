#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shutil.copy('/etc/pam.d/system-auth', '/etc/pam.d/system-auth.bak')
    shutil.copy('/etc/pam.d/password-auth', '/etc/pam.d/password-auth.bak')

    shellexec(R"sed -i '/password\s*sufficient\s*pam_unix.so/ s/sha512/sha512 remember=5/' /etc/pam.d/system-auth")
    shellexec(R"sed -i '/password\s*sufficient\s*pam_unix.so/ s/sha512/sha512 remember=5/' /etc/pam.d/password-auth")

    yield None

    ## Tear-down
    shutil.move('/etc/pam.d/system-auth.bak', '/etc/pam.d/system-auth')
    shutil.move('/etc/pam.d/password-auth.bak', '/etc/pam.d/password-auth')


def test_integration_audit_password_reuse_is_limited_pass(setup_to_pass):
    state = CISAudit().audit_password_reuse_is_limited()
    assert state == 0


def test_integration_audit_password_reuse_is_limited_pass_fail():
    state = CISAudit().audit_password_reuse_is_limited()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
