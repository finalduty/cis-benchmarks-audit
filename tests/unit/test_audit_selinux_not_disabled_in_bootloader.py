#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch
import cis_audit
import pytest
import os

test = cis_audit.CISAudit()


def mock_shellexec_pass(self, cmd):
    returncode = 1
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_shellexec_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = [
        '    linux16 /vmlinuz-0-rescue-2678564b6116e34e9ce30f45f866738a root=UUID=1726d31e-e474-4b79-a451-e0a9b86459a0 ro net.ifnames=0 biosdevname=0 crashkernel=auto rhgb quiet selinux=0',
        '',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_os_walk(top, topdown=True, onerror=None, followlinks=False):
    ## https://docs.python.org/3/library/os.html#os.walk
    ## Generate the file names in a directory tree by walking the tree either top-down or bottom-up. For each directory in the tree rooted at directory top (including top itself), it yields a 3-tuple (dirpath, dirnames, filenames).

    if top == '/boot/':
        rows = [
            ('/boot', ['efi', 'grub2', 'grub'], ['initramfs-0-rescue-2678564b6116e34e9ce30f45f866738a.img', 'vmlinuz-0-rescue-2678564b6116e34e9ce30f45f866738a', '.vmlinuz-3.10.0-1160.45.1.el7.x86_64.hmac', 'System.map-3.10.0-1160.45.1.el7.x86_64', 'config-3.10.0-1160.45.1.el7.x86_64', 'symvers-3.10.0-1160.45.1.el7.x86_64.gz', 'vmlinuz-3.10.0-1160.45.1.el7.x86_64', 'initramfs-3.10.0-1160.45.1.el7.x86_64.img']),
            ('/boot/efi', ['EFI'], []),
            ('/boot/efi/EFI', ['centos'], []),
            ('/boot/efi/EFI/centos', [], []),
            ('/boot/grub2', ['locale', 'fonts'], ['device.map', 'grubenv', 'grub.cfg']),
            ('/boot/grub2/locale', [], []),
            ('/boot/grub2/fonts', [], ['unicode.pf2']),
            ('/boot/grub', [], ['splash.xpm.gz']),
        ]

    if rows:
        for row in rows:
            yield row


def mock_os_walk_no_match(top, topdown=True, onerror=None, followlinks=False):
    ## https://docs.python.org/3/library/os.html#os.walk
    ## Generate the file names in a directory tree by walking the tree either top-down or bottom-up. For each directory in the tree rooted at directory top (including top itself), it yields a 3-tuple (dirpath, dirnames, filenames).

    if top == '/boot/':
        rows = [
            ('/boot', ['efi', 'grub'], ['initramfs-0-rescue-2678564b6116e34e9ce30f45f866738a.img', 'vmlinuz-0-rescue-2678564b6116e34e9ce30f45f866738a', '.vmlinuz-3.10.0-1160.45.1.el7.x86_64.hmac', 'System.map-3.10.0-1160.45.1.el7.x86_64', 'config-3.10.0-1160.45.1.el7.x86_64', 'symvers-3.10.0-1160.45.1.el7.x86_64.gz', 'vmlinuz-3.10.0-1160.45.1.el7.x86_64', 'initramfs-3.10.0-1160.45.1.el7.x86_64.img']),
            ('/boot/efi', ['EFI'], []),
            ('/boot/efi/EFI', ['centos'], []),
            ('/boot/efi/EFI/centos', [], []),
            ('/boot/grub2/locale', [], []),
            ('/boot/grub2/fonts', [], ['unicode.pf2']),
            ('/boot/grub', [], ['splash.xpm.gz']),
        ]

    if rows:
        for row in rows:
            yield row


@patch.object(os, "walk", mock_os_walk)
@patch.object(cis_audit.CISAudit, "_shellexec", mock_shellexec_pass)
def test_audit_selinux_not_disabled_in_bootloader_pass():
    state = test.audit_selinux_not_disabled_in_bootloader()
    assert state == 0


@patch.object(os, "walk", mock_os_walk)
@patch.object(cis_audit.CISAudit, "_shellexec", mock_shellexec_fail)
def test_audit_selinux_not_disabled_in_bootloader_fail():
    state = test.audit_selinux_not_disabled_in_bootloader()
    assert state == 2


@patch.object(os, "walk", mock_os_walk_no_match)
@patch.object(cis_audit.CISAudit, "_shellexec", mock_shellexec_fail)
def test_audit_selinux_not_disabled_in_bootloader_fail_no_match():
    state = test.audit_selinux_not_disabled_in_bootloader()
    assert state == -1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
