#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
        '-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
    ]
    auditctl_rules = [
        "-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -F 'auid>=1000' -F 'auid!=4294967295' -S execve -F key=actions",
        "-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -F 'auid>=1000' -F 'auid!=4294967295' -S execve -F key=actions",
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


def test_integration_audit_events_for_system_administrator_commands_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_for_system_administrator_commands_are_collected()
    assert state == 0


def test_integration_audit_events_for_system_administrator_commands_are_collected_fail():
    state = CISAudit().audit_events_for_system_administrator_commands_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
