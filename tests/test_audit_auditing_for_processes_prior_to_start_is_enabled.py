#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_auditing_for_processes_prior_to_start_is_enabled_pass_efidir(self, cmd):
    if 'find /boot/efi/EFI' in cmd:
        stdout = ['/boot/efi/EFI/centos/grub.cfg', '']
    elif R'grep "^\s*linux"' in cmd:
        stdout = ['PASSED', '']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_auditing_for_processes_prior_to_start_is_enabled_pass_grubdir(self, cmd):
    if 'find /boot ' in cmd:
        stdout = ['/boot/grub2/grub.cfg', '']
    elif R'grep "^\s*linux"' in cmd:
        stdout = ['PASSED', '']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_auditing_for_processes_prior_to_start_is_enabled_fail(self, cmd):
    if R'grep "^\s*linux"' in cmd:
        stdout = ['FAILED', '']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_auditing_for_processes_prior_to_start_is_enabled_pass_efidir)
def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_efidir():
    state = test.audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_auditing_for_processes_prior_to_start_is_enabled_pass_grubdir)
def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_grubdir():
    state = test.audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_auditing_for_processes_prior_to_start_is_enabled_fail)
def test_audit_auditing_for_processes_prior_to_start_is_enabled_fail():
    state = test.audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
