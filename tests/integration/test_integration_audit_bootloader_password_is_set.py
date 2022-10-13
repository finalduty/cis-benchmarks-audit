#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec

test = CISAudit()


@pytest.fixture
def setup_to_pass():
    ## Setup
    ## Get the value by running 'grub2-setpassword', then checking /boot/grub2/user.cfg
    shellexec('echo GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.A03A140DBAA0676BF9597209D32653B5A47D0C51C6EA7EDBD6648337E6DA881C70AD1E043AA4A2C3A10EB8D244DD9E346109C5EC732124E165DF59839F8119DB.10AC2C6980F4ABDBDBEDA4FF8C624A0DF1FAB61786B1C87B67219BCD26BAA363CB475D116F2050585CC47AB6CA6C9676F22D8084653D87EB0B4A6A6FC76E393D > /boot/grub2/user.cfg')

    yield None

    ## Tear-down
    os.remove('/boot/grub2/user.cfg')


def test_integration_audit_bootloader_password_set_pass(setup_to_pass):
    state = test.audit_bootloader_password_is_set()
    assert state == 0


def test_integration_audit_bootloader_password_set_fail():
    state = test.audit_bootloader_password_is_set()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
