#!/usr/bin/env python3

import pytest
import os

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        '-w /sbin/insmod -p x -k modules',
        '-w /sbin/rmmod -p x -k modules',
        '-w /sbin/modprobe -p x -k modules',
        '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
    ]
    auditctl_rules = [
        '-w /sbin/insmod -p x -k modules',
        '-w /sbin/rmmod -p x -k modules',
        '-w /sbin/modprobe -p x -k modules',
        '-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules',
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


def test_integration_audit_events_for_kernel_module_loading_and_unloading_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_for_kernel_module_loading_and_unloading_are_collected()
    assert state == 0


def test_integration_audit_events_for_kernel_module_loading_and_unloading_are_collected_fail():
    state = CISAudit().audit_events_for_kernel_module_loading_and_unloading_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
