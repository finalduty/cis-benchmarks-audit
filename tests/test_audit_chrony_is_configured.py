#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_chrony_configured_pass(self, cmd):
    stderr = ['']
    returncode = 0

    if 'is-enabled' in cmd:
        stdout = ['enabled']
    elif 'is-active' in cmd:
        stdout = ['active']
    elif 'server' in cmd:
        stdout = ['server 0.centos.pool.ntp.org iburst', 'server 1.centos.pool.ntp.org iburst', 'server 2.centos.pool.ntp.org iburst', 'server 3.centos.pool.ntp.org iburst']
    elif 'ps aux' in cmd:
        stdout = ['chrony']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_chrony_configured_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['']

    if 'is-enabled' in cmd:
        stdout = ['disabled']
    elif 'is-active' in cmd:
        stdout = ['inactive']
    elif 'server' in cmd:
        returncode = 1
    elif 'ps aux' in cmd:
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


class TestChronyIsConfigured:
    @patch.object(CISAudit, "_shellexec", mock_chrony_configured_pass)
    def test_chrony_is_configure_pass(self):
        state = test.audit_chrony_is_configured()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_chrony_configured_fail)
    def test_chrony_is_configure_fail(self):
        state = test.audit_chrony_is_configured()
        assert state == 15


if __name__ == '__main__':
    pytest.main([__file__])
