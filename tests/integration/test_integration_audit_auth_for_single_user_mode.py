#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    ## Create copy of original file before modification
    shutil.copy('/usr/lib/systemd/system/rescue.service', '/usr/lib/systemd/system/rescue.service.bak')

    ## Update the file
    shellexec("sed -i -- '/^ExecStart=/ s|^.*|ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --no-block default\"|' /usr/lib/systemd/system/rescue.service")
    print(shellexec('grep ExecStart= /usr/lib/systemd/system/rescue.service'))

    yield None

    ## Replace modified file with original
    shutil.move('/usr/lib/systemd/system/rescue.service.bak', '/usr/lib/systemd/system/rescue.service')


def test_integrate_auth_for_single_user_mode_pass():
    state = CISAudit().audit_auth_for_single_user_mode()
    assert state == 0


def test_integrate_auth_for_single_user_mode_fail(setup_to_fail):
    state = CISAudit().audit_auth_for_single_user_mode()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
