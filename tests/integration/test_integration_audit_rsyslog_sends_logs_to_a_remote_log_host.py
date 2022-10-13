#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_1():
    ## Setup
    shellexec("echo '*.* @@192.168.2.100' >> /etc/rsyslog.d/pytest.conf")

    yield None

    ## Tear-down
    os.remove('/etc/rsyslog.d/pytest.conf')


@pytest.fixture
def setup_to_pass_2():
    ## Setup
    with open('/etc/rsyslog.d/pytest.conf', 'w') as f:
        f.writelines(
            [
                '*.* action(type="omfwd" target="192.168.2.100" port="514" protocol="tcp"',
                '           action.resumeRetryCount="100"',
                '           queue.type="LinkedList" queue.size="1000")',
                '',
            ]
        )

    yield None

    ## Tear-down
    os.remove('/etc/rsyslog.d/pytest.conf')


def test_audit_rsyslog_sends_logs_to_a_remote_log_host_pass_type1(setup_to_pass_1):
    state = CISAudit().audit_rsyslog_sends_logs_to_a_remote_log_host()
    assert state == 0


def test_audit_rsyslog_sends_logs_to_a_remote_log_host_pass_type2(setup_to_pass_2):
    state = CISAudit().audit_rsyslog_sends_logs_to_a_remote_log_host()
    assert state == 0


def test_audit_rsyslog_sends_logs_to_a_remote_log_host_fail():
    state = CISAudit().audit_rsyslog_sends_logs_to_a_remote_log_host()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
