#!/usr/bin/env python3

import shutil
import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    print(shellexec('yum install -q -y ntp'))
    shutil.copy('/etc/ntp.conf', '/etc/ntp.conf.bak')
    shellexec("sed -i 's/restrict default.*/restrict default kod nomodify notrap nopeer noquery/' /etc/ntp.conf")

    print(shellexec('systemctl enable ntpd'))
    print(shellexec('systemctl start ntpd'))

    yield None

    print(shellexec('yum remove -q -y ntp'))
    print(shellexec('systemctl disable ntpd'))
    print(shellexec('systemctl start chronyd'))


def test_integration_audit_ntp_is_configured_pass(setup_to_pass):
    state = CISAudit().audit_ntp_is_configured()
    assert state == 0


def test_integration_audit_ntp_is_configured_fail():
    state = CISAudit().audit_ntp_is_configured()
    assert state == 31


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
