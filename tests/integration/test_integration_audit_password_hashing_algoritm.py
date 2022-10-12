#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shutil.copy('/etc/pam.d/system-auth', '/etc/pam.d/system-auth.bak')
    shutil.copy('/etc/pam.d/password-auth', '/etc/pam.d/password-auth.bak')

    shellexec("sed -i 's/sha512/md5/' /etc/pam.d/system-auth")
    shellexec("sed -i 's/sha512/md5/' /etc/pam.d/password-auth")

    yield None

    ## Tear-down
    shutil.move('/etc/pam.d/system-auth.bak', '/etc/pam.d/system-auth')
    shutil.move('/etc/pam.d/password-auth.bak', '/etc/pam.d/password-auth')


def test_integration_audit_password_hashing_algorithm_pass():
    state = CISAudit().audit_password_hashing_algorithm()
    assert state == 0


def test_integration_audit_password_hashing_algorithm_fail(setup_to_fail):
    state = CISAudit().audit_password_hashing_algorithm()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
