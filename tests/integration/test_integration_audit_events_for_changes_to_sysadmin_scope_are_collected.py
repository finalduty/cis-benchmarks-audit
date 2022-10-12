#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    rules = [
        '-w /etc/sudoers -p wa -k scope',
        '-w /etc/sudoers.d -p wa -k scope',
    ]

    for rule in rules:
        shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules')
        shellexec(f'auditctl {rule}')

    yield None

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_for_changes_to_sysadmin_scope_are_collected_pass(setup_to_pass):
    state = CISAudit().audit_events_for_changes_to_sysadmin_scope_are_collected()
    assert state == 0


def test_integration_audit_events_for_changes_to_sysadmin_scope_are_collected_fail():
    state = CISAudit().audit_events_for_changes_to_sysadmin_scope_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
