#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit

from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shellexec('iptables -P INPUT DROP')
    shellexec('iptables -P FORWARD DROP')
    shellexec('iptables -P OUTPUT DROP')
    shellexec('ip6tables -P INPUT DROP')
    shellexec('ip6tables -P FORWARD DROP')
    shellexec('ip6tables -P OUTPUT DROP')

    yield None

    shellexec('iptables -P INPUT ACCEPT')
    shellexec('iptables -P FORWARD ACCEPT')
    shellexec('iptables -P OUTPUT ACCEPT')
    shellexec('ip6tables -P INPUT ACCEPT')
    shellexec('ip6tables -P FORWARD ACCEPT')
    shellexec('ip6tables -P OUTPUT ACCEPT')


def test_integration_audit_iptables_default_deny_pass_ipv4(setup_to_pass):
    state = CISAudit().audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 0


def test_integration_audit_iptables_default_deny_fail_ipv4():
    state = CISAudit().audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 7


def test_integration_audit_iptables_default_deny_pass_ipv6(setup_to_pass):
    state = CISAudit().audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 0


def test_integration_audit_iptables_default_deny_fail_ipv6():
    state = CISAudit().audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
