#!/usr/bin/env python3


import pytest
import shutil

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    shutil.copy('/etc/audit/auditd.conf', '/etc/audit/auditd.conf.bak')
    shellexec('sed -i "s/^.*max_log_file =/max_log_file =/" /etc/audit/auditd.conf')

    yield None

    shutil.move('/etc/audit/auditd.conf.bak', '/etc/audit/auditd.conf')


@pytest.fixture()
def setup_to_fail():
    shutil.copy('/etc/audit/auditd.conf', '/etc/audit/auditd.conf.bak')
    shellexec('sed -i "s/^.*max_log_file =/#max_log_file =/" /etc/audit/auditd.conf')

    yield None

    shutil.move('/etc/audit/auditd.conf.bak', '/etc/audit/auditd.conf')


def test_integrate_audit_audit_log_size_is_configured_pass(setup_to_pass):
    state = CISAudit().audit_audit_log_size_is_configured()
    assert state == 0


def test_integrate_audit_audit_log_size_is_configured_fail(setup_to_fail):
    state = CISAudit().audit_audit_log_size_is_configured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
