#!/usr/bin/env python3

import shutil
from cis_audit import CISAudit

import pytest
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail_disabled():
    ## Setup
    shutil.copy('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')
    shellexec(R"sed -i '/\slinux/ s/$/ selinux=0/' /boot/grub2/grub.cfg")

    yield None

    ## Tear-down
    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


@pytest.fixture
def setup_to_fail_permissive():
    ## Setup
    shutil.copy('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')
    shellexec(R"sed -i '/\slinux/ s/$/ enforcing=0/' /boot/grub2/grub.cfg")

    yield None

    ## Tear-down
    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


@pytest.fixture
def setup_to_fail_file_not_found():
    ## Setup
    shutil.move('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')

    yield None

    ## Tear-down
    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


def test_integration_audit_selinux_not_disabled_in_bootloader_pass():
    state = CISAudit().audit_selinux_not_disabled_in_bootloader()
    assert state == 0


def test_integration_audit_selinux_not_disabled_in_bootloader_fail_disabled(setup_to_fail_disabled):
    state = CISAudit().audit_selinux_not_disabled_in_bootloader()
    assert state == 2


def test_integration_audit_selinux_not_disabled_in_bootloader_fail_permissive(setup_to_fail_permissive):
    state = CISAudit().audit_selinux_not_disabled_in_bootloader()
    assert state == 2


def test_integration_audit_selinux_not_disabled_in_bootloader_fail_no_match(setup_to_fail_file_not_found):
    state = CISAudit().audit_selinux_not_disabled_in_bootloader()
    assert state == -1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
