#!/usr/bin/env python3

import shutil
import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shutil.copy('/etc/audit/auditd.conf', '/etc/audit/auditd.conf.bak')
    shellexec("sed -i '/^space_left_action/ s/=.*/= email/' /etc/audit/auditd.conf")
    # shellexec("sed -i '/^action_mail_acct/ s/=.*/= root/' /etc/audit/auditd.conf")
    shellexec("sed -i '/^admin_space_left_action/ s/=.*/= halt/' /etc/audit/auditd.conf")

    yield None

    ## Tear-down
    shutil.move('/etc/audit/auditd.conf.bak', '/etc/audit/auditd.conf')


@pytest.fixture
def setup_to_fail():
    ## Setup
    shutil.copy('/etc/audit/auditd.conf', '/etc/audit/auditd.conf.bak')
    # shellexec("sed -i '/^space_left_action/ s/=.*/= email/' /etc/audit/auditd.conf")
    shellexec("sed -i '/^action_mail_acct/ s/=.*/= pytest/' /etc/audit/auditd.conf")
    # shellexec("sed -i '/^admin_space_left_action/ s/=.*/= halt/' /etc/audit/auditd.conf")

    yield None

    ## Tear-down
    shutil.move('/etc/audit/auditd.conf.bak', '/etc/audit/auditd.conf')


def test_integration_audit_system_is_disabled_when_audit_logs_are_full_pass(setup_to_pass):
    state = CISAudit().audit_system_is_disabled_when_audit_logs_are_full()
    assert state == 0


def test_integration_audit_system_is_disabled_when_audit_logs_are_full_fail(setup_to_fail):
    state = CISAudit().audit_system_is_disabled_when_audit_logs_are_full()
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
