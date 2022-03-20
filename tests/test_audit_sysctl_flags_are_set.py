#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_sysctl_flags_are_set_pass(self, cmd):
    if 'net.ipv6.conf.all.disable_ipv6' in cmd:
        stdout = ['net.ipv6.conf.all.disable_ipv6 = 1', '']
    elif 'net.ipv6.conf.default.disable_ipv6' in cmd:
        stdout = ['net.ipv6.conf.default.disable_ipv6 = 1', '']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_sysctl_flags_are_set_fail(self, cmd):
    if 'grub' in cmd:
        stdout = ['pytest']
    else:
        stdout = ['']

    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestSysctlFlagsAreSet:
    test = CISAudit()
    test_id = '1.1'
    flags = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"]

    @patch.object(CISAudit, "_shellexec", mock_sysctl_flags_are_set_pass)
    def test_sysctl_flags_are_set_pass(self):
        value = 1
        state = self.test.audit_sysctl_flags_are_set(self.flags, value)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_sysctl_flags_are_set_fail)
    def test_sysctl_flags_are_set_fail(self):
        value = 0
        state = self.test.audit_sysctl_flags_are_set(self.flags, value)
        assert state == 15

if __name__ == '__main__':
    pytest.main([__file__])
