#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_auditing_for_processes_prior_to_start_is_enabled_pass(self, cmd):
    if cmd.startswith('find /boot/efi/EFI'):
        stdout = ['/boot/efi/EFI/centos/grub.cfg', '']
    elif cmd.startswith('find /boot '):
        stdout = ['/boot/grub2/grub.cfg', '']
    elif 'grub.cfg' in cmd:
        stdout = ['PASSED', '']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_auditing_for_processes_prior_to_start_is_enabled_fail(self, cmd):
    if 'grub.cfg' in cmd:
        stdout = ['FAILED', '']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_auditing_for_processes_prior_to_start_is_enabled_pass)
def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass():
    state = test.audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_auditing_for_processes_prior_to_start_is_enabled_fail)
def test_audit_auditing_for_processes_prior_to_start_is_enabled_fail():
    state = test.audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
