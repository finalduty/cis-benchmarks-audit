#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('echo "pytest:!!:1001:1001::/home/pytest:/bin/bash" >> /etc/passwd')

    yield None

    shellexec('sed -i "/pytest/d" /etc/passwd')


def test_integration_audit_etc_passwd_accounts_use_shadowed_passwords_pass():
    state = CISAudit().audit_etc_passwd_accounts_use_shadowed_passwords()
    assert state == 0


def test_integration_audit_etc_passwd_accounts_use_shadowed_passwords_fail(setup_to_fail):
    state = CISAudit().audit_etc_passwd_accounts_use_shadowed_passwords()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
