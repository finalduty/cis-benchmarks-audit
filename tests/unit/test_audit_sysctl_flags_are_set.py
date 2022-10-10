#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_sysctl_flags_are_set_pass(self, cmd):
    if 'net.ipv6.conf.all.disable_ipv6' in cmd:
        stdout = ['net.ipv6.conf.all.disable_ipv6 = 1']
    elif 'net.ipv6.conf.default.disable_ipv6' in cmd:
        stdout = ['net.ipv6.conf.default.disable_ipv6 = 1']

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


test = CISAudit()
flags = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"]


@patch.object(CISAudit, "_shellexec", mock_sysctl_flags_are_set_pass)
def test_audit_sysctl_flags_are_set_pass():
    value = 1
    state = test.audit_sysctl_flags_are_set(flags, value)
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_sysctl_flags_are_set_fail)
def test_audit_sysctl_flags_are_set_fail():
    value = 0
    state = test.audit_sysctl_flags_are_set(flags, value)
    assert state == 15


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
