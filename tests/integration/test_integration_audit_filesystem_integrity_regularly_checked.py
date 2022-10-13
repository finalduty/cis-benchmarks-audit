#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_crontab():
    ## Setup
    shellexec('echo "0 5 * * * /usr/sbin/aide --check" > /etc/cron.d/aide-check')

    yield None

    ## Tear-down
    os.remove('/etc/cron.d/aide-check')


@pytest.fixture
def setup_to_pass_systemd():
    ## Setup
    shellexec('yum install -y aide')

    with open('/etc/systemd/system/aidecheck.service', 'w') as f:
        f.writelines(
            [
                '[Unit]\n',
                'Description=Aide Check\n',
                '\n',
                '[Service]\n',
                'Type=simple\n',
                'ExecStart=/usr/sbin/aide --check\n',
                '\n',
                '[Install]\n',
                'WantedBy=multi-user.target\n',
            ]
        )

    with open('/etc/systemd/system/aidecheck.timer', 'w') as f:
        f.writelines(
            [
                '[Unit]\n',
                'Description=Aide check every day at 5AM\n',
                '\n',
                '[Timer]\n',
                'OnCalendar=*-*-* 05:00:00\n',
                'Unit=aidecheck.service\n',
                '\n',
                '[Install]\n',
                'WantedBy=multi-user.target\n',
            ]
        )

    shellexec('systemctl enable aidecheck aidecheck.timer')
    shellexec('systemctl start aidecheck.timer')

    yield None

    ## Tear-down
    os.remove('/etc/systemd/system/aidecheck.service')
    os.remove('/etc/systemd/system/aidecheck.timer')

    shellexec('yum autoremove -y aide')


def test_integration_filesystem_integrity_pass_crontab(setup_to_pass_crontab):
    state = CISAudit().audit_filesystem_integrity_regularly_checked()
    assert state == 0


def test_integration_filesystem_integrity_pass_systemd(setup_to_pass_systemd):
    state = CISAudit().audit_filesystem_integrity_regularly_checked()
    assert state == 0


def test_integration_filesystem_integrity_fail():
    state = CISAudit().audit_filesystem_integrity_regularly_checked()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
