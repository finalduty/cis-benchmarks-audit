#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_iptables_loopback_is_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INPUT' in cmd:
        stdout = [
            '-P INPUT ACCEPT',
            '-A INPUT -i lo -j ACCEPT',
            '-A INPUT -s 127.0.0.0/8 -j DROP',
        ]
    elif 'OUTPUT' in cmd:
        stdout = [
            '-P OUTPUT ACCEPT',
            '-A OUTPUT -o lo -j ACCEPT',
        ]
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_loopback_is_configured_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


## IPv4
@patch.object(CISAudit, "_shellexec", mock_iptables_loopback_is_configured_pass)
def test_audit_iptables_loopback_is_configured_pass():
    state = test.audit_iptables_loopback_is_configured(ip_version='ipv4')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_loopback_is_configured_fail)
def test_audit_iptables_loopback_is_configured_fail():
    state = test.audit_iptables_loopback_is_configured(ip_version='ipv4')
    assert state == 31


## IPv6
@patch.object(CISAudit, "_shellexec", mock_iptables_loopback_is_configured_pass)
def test_audit_ip6tables_loopback_is_configured_pass():
    state = test.audit_iptables_loopback_is_configured(ip_version='ipv6')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_loopback_is_configured_fail)
def test_audit_ip6tables_loopback_is_configured_fail():
    state = test.audit_iptables_loopback_is_configured(ip_version='ipv6')
    assert state == 31


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
