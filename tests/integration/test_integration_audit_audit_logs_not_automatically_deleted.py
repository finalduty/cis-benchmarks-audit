#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    shellexec('sed -i "s/^.*max_log_file_action =.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf')


@pytest.fixture()
def setup_to_fail():
    shellexec('sed -i "s/^.*max_log_file_action =.*/max_log_file_action = ROTATE/" /etc/audit/auditd.conf')


def test_audit_audit_logs_not_automatically_deleted_pass(setup_to_pass):
    state = CISAudit().audit_audit_logs_not_automatically_deleted()
    assert state == 0


def test_audit_audit_logs_not_automatically_deleted_fail(setup_to_fail):
    state = CISAudit().audit_audit_logs_not_automatically_deleted()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
