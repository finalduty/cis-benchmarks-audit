#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_rsyslog_sends_logs_to_a_remote_log_host_pass(self, cmd):
    if 'action' in cmd:
        stdout = [
            ' *.* action(type="omfwd" target="192.168.2.100" port="514" protocol="tcp" action.resumeRetryCount="100" queue.type="LinkedList" queue.size="1000")',
            '',
        ]
    else:
        stdout = [
            '*.* @@192.168.2.100',
            '',
        ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_rsyslog_sends_logs_to_a_remote_log_host_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_rsyslog_sends_logs_to_a_remote_log_host_pass)
def test_audit_rsyslog_sends_logs_to_a_remote_log_host_pass():
    state = test.audit_rsyslog_sends_logs_to_a_remote_log_host()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_rsyslog_sends_logs_to_a_remote_log_host_fail)
def test_audit_rsyslog_sends_logs_to_a_remote_log_host_fail():
    state = test.audit_rsyslog_sends_logs_to_a_remote_log_host()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
