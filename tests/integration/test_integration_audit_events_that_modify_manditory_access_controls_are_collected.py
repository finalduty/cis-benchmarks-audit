#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    rules = [
        '-w /etc/selinux -p wa -k MAC-policy',
        '-w /usr/share/selinux -p wa -k MAC-policy',
    ]

    for rule in rules:
        print(shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules'))
        print(shellexec(f'auditctl {rule}'))

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_that_modify_mandatory_access_controls_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_that_modify_mandatory_access_controls_are_collected()
    assert state == 0


def test_integration_audit_events_that_modify_mandatory_access_controls_are_collected_fail():
    state = CISAudit().audit_events_that_modify_mandatory_access_controls_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
