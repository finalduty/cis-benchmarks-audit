#!/usr/bin/env python3

import pytest
import os

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
    ]
    auditctl_rules = [
        "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
        "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
        "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
        "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
        "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
        "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F 'auid>=1000' -F 'auid!=4294967295' -k perm_mod",
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


def test_integration_audit_events_for_discretionary_access_control_changes_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_for_discretionary_access_control_changes_are_collected()
    assert state == 0


def test_integration_audit_events_for_discretionary_access_control_changes_are_collected_fail():
    state = CISAudit().audit_events_for_discretionary_access_control_changes_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
