#!/usr/bin/env python3

import shutil
import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shutil.copy('/etc/systemd/journald.conf', '/etc/systemd/journald.conf.bak')
    shellexec("sed -i 's/.*ForwardToSyslog=.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf")

    yield None

    shutil.move('/etc/systemd/journald.conf.bak', '/etc/systemd/journald.conf')


def test_integration_audit_journald_configured_to_send_logs_to_rsyslog_pass(setup_to_pass):
    state = CISAudit().audit_journald_configured_to_send_logs_to_rsyslog()
    assert state == 0


def test_integration_audit_journald_configured_to_send_logs_to_rsyslog_fail():
    state = CISAudit().audit_journald_configured_to_send_logs_to_rsyslog()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
