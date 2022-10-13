#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    shutil.copy('/etc/postfix/main.cf', '/etc/postfix/main.cf.bak')
    print(shellexec("sed -i 's/^inet_interfaces = .*/inet_interfaces = all/' /etc/postfix/main.cf"))
    print(shellexec('systemctl restart postfix'))

    yield None

    shutil.move('/etc/postfix/main.cf.bak', '/etc/postfix/main.cf')
    print(shellexec('systemctl restart postfix'))


def test_integration_mta_is_localhost_pass():
    state = CISAudit().audit_mta_is_localhost_only()
    assert state == 0


def test_integration_mta_is_localhost_fail(setup_to_fail):
    state = CISAudit().audit_mta_is_localhost_only()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
