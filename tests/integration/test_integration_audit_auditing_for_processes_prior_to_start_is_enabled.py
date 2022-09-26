#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass_grub():
    shellexec("sed -i '/linux16/ s/$/ audit=1/' /boot/grub2/grub.cfg")


@pytest.fixture()
def setup_to_fail():
    shellexec("sed -i '/linux16/ s/audit=1//' /boot/grub2/grub.cfg")


# def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_efidir():
#    state = CISAudit().audit_auditing_for_processes_prior_to_start_is_enabled()
#    assert state == 0


def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_grubdir(setup_to_pass_grub):
    state = CISAudit().audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


def test_audit_auditing_for_processes_prior_to_start_is_enabled_fail(setup_to_fail):
    state = CISAudit().audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
