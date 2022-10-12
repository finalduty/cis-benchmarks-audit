#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
        '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        '-a always,exit -F arch=b32 -S clock_settime -k time-change',
        '-w /etc/localtime -p wa -k time-change',
    ]
    auditctl_rules = [
        '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
        '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        '-a always,exit -F arch=b32 -S clock_settime -k time-change',
        '-w /etc/localtime -p wa -k time-change',
    ]

    for rule in file_rules:
        print(shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules'))

    for rule in auditctl_rules:
        print(shellexec(f'auditctl {rule}'))

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_that_modify_datetime_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_that_modify_datetime_are_collected()
    assert state == 0


def test_integration_audit_events_that_modify_datetime_are_collected_fail():
    state = CISAudit().audit_events_that_modify_datetime_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
