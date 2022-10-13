#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    rules = [
        '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
        '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
        '-w /etc/issue -p wa -k system-locale',
        '-w /etc/issue.net -p wa -k system-locale',
        '-w /etc/hosts -p wa -k system-locale',
        '-w /etc/sysconfig/network -p wa -k system-locale',
    ]

    for rule in rules:
        print(shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules'))
        print(shellexec(f'auditctl {rule}'))

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_that_modify_network_environment_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_that_modify_network_environment_are_collected()
    assert state == 0


def test_integration_audit_events_that_modify_network_environment_are_collected_fail():
    state = CISAudit().audit_events_that_modify_network_environment_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
