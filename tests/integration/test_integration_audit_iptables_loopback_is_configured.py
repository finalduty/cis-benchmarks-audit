#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('iptables -A INPUT -i lo -j ACCEPT')
    shellexec('iptables -A INPUT -s 127.0.0.1/8 -j DROP')
    shellexec('iptables -A OUTPUT -o lo -j ACCEPT')

    shellexec('ip6tables -A INPUT -i lo -j ACCEPT')
    shellexec('ip6tables -A INPUT -s ::1 -j DROP')
    shellexec('ip6tables -A OUTPUT -o lo -j ACCEPT')

    yield None

    ## Tear-down
    shellexec('iptables -F')
    shellexec('ip6tables -F')


## IPv4
def test_integration_audit_iptables_loopback_is_configured_pass_ipv4(setup_to_pass):
    state = CISAudit().audit_iptables_loopback_is_configured(ip_version='ipv4')
    assert state == 0


def test_integration_audit_iptables_loopback_is_configured_fail_ipv4():
    state = CISAudit().audit_iptables_loopback_is_configured(ip_version='ipv4')
    assert state == 7


## IPv6
def test_integration_audit_iptables_loopback_is_configured_pass_ipv6(setup_to_pass):
    state = CISAudit().audit_iptables_loopback_is_configured(ip_version='ipv6')
    assert state == 0


def test_integration_audit_iptables_loopback_is_configured_fail_ipv6():
    state = CISAudit().audit_iptables_loopback_is_configured(ip_version='ipv6')
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
