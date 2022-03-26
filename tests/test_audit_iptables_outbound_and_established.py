#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_iptables_outbound_and_established_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = [
        '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT',
        '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT',
        '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT',
        '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT',
        '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT',
        '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT',
    ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_outbound_and_established_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


## IPv4
@patch.object(CISAudit, "_shellexec", mock_iptables_outbound_and_established_pass)
def test_audit_iptables_outbound_and_established_ipv4_pass():
    state = test.audit_iptables_outbound_and_established(ip_version='ipv4')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_outbound_and_established_fail)
def test_audit_iptables_outbound_and_established_ipv4_fail():
    state = test.audit_iptables_outbound_and_established(ip_version='ipv4')
    assert state == 63


## IPv6
@patch.object(CISAudit, "_shellexec", mock_iptables_outbound_and_established_pass)
def test_audit_ip6tables_outbound_and_established_ipv4_pass():
    state = test.audit_iptables_outbound_and_established(ip_version='ipv6')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_outbound_and_established_fail)
def test_audit_ip6tables_outbound_and_established_ipv4_fail():
    state = test.audit_iptables_outbound_and_established(ip_version='ipv6')
    assert state == 63


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
