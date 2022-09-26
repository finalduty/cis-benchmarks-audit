#!/usr/bin/env python3

from types import SimpleNamespace

import pytest

from cis_audit import CISAudit


def mock_bootloader_password_pass(self, cmd):
    output = ['GRUB2_PASSWORD=supersecret']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_bootloader_password_fail_blank(self, cmd):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_bootloader_password_fail_commented(self, cmd):
    output = ['#GRUB2_PASSWORD=supersecret']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


# def test_bootloader_password_set_pass(self):
#    state = self.test.audit_bootloader_password_is_set()
#    assert state == 0


# def test_bootloader_password_set_fail_blank(self):
#    state = self.test.audit_bootloader_password_is_set()
#    assert state == 1


# def test_bootloader_password_set_fail_commented(self):
#    state = self.test.audit_bootloader_password_is_set()
#    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
