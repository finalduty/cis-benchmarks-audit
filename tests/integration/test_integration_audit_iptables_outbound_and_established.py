#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_ipv4():
    shellexec('iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT')
    shellexec('iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT')
    shellexec('iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT')

    yield None

    shellexec('iptables -F')


@pytest.fixture
def setup_to_pass_ipv6():
    shellexec('ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT')
    shellexec('ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT')
    shellexec('ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT')
    shellexec('ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT')

    yield None

    shellexec('ip6tables -F')


## IPv4
def test_integration_audit_iptables_outbound_and_established_pass_ipv4(setup_to_pass_ipv4):
    state = CISAudit().audit_iptables_outbound_and_established(ip_version='ipv4')
    assert state == 0


def test_integration_audit_iptables_outbound_and_established_fail_ipv4():
    state = CISAudit().audit_iptables_outbound_and_established(ip_version='ipv4')
    assert state == 63


## IPv6
def test_integration_audit_iptables_outbound_and_established_pass_ipv6(setup_to_pass_ipv6):
    state = CISAudit().audit_iptables_outbound_and_established(ip_version='ipv6')
    assert state == 0


def test_integration_audit_iptables_outbound_and_established_fail_ipv6():
    state = CISAudit().audit_iptables_outbound_and_established(ip_version='ipv6')
    assert state == 63


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
