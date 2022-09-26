#!/usr/bin/env python3


import pytest

from cis_audit import CISAudit
from tests.integration import shellexec

test = CISAudit()


@pytest.fixture()
def setup_to_pass():
    shellexec('sed -i "s/^.*max_log_file =/max_log_file =/" /etc/audit/auditd.conf')


@pytest.fixture()
def setup_to_fail():
    shellexec('sed -i "s/^.*max_log_file =/#max_log_file =/" /etc/audit/auditd.conf')


def test_integrate_audit_audit_log_size_is_configured_pass(setup_to_pass):
    state = test.audit_audit_log_size_is_configured()
    assert state == 0


def test_integrate_audit_audit_log_size_is_configured_fail(setup_to_fail):
    state = test.audit_audit_log_size_is_configured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
