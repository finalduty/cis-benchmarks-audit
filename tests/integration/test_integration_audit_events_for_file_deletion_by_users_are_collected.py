#!/usr/bin/env python3

import pytest
import os

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
    ]
    auditctl_rules = [
        "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F 'auid>=1000' -F 'auid!=4294967295' -F key=delete",
        "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F 'auid>=1000' -F 'auid!=4294967295' -F key=delete",
    ]

    for rule in file_rules:
        shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules')

    for rule in auditctl_rules:
        shellexec(f'auditctl {rule}')

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_for_file_deletion_by_users_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_for_file_deletion_by_users_are_collected()
    assert state == 0


def test_integration_audit_events_for_file_deletion_by_users_are_collected_fail():
    state = CISAudit().audit_events_for_file_deletion_by_users_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
