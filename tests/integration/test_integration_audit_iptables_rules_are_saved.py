#!/usr/bin/env python3

import os
import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_ipv4():
    if os.path.exists('/etc/sysconfig/iptables'):
        shutil.copy2('/etc/sysconfig/iptables', '/etc/sysconfig/iptables.bak')

    shellexec('iptables-save > /etc/sysconfig/iptables')

    yield None

    if os.path.exists('/etc/sysconfig/iptables.bak'):
        shutil.move('/etc/sysconfig/iptables.bak', '/etc/sysconfig/iptables')
    else:
        os.remove('/etc/sysconfig/iptables.bak')


@pytest.fixture
def setup_to_pass_ipv6():
    if os.path.exists('/etc/sysconfig/ip6tables'):
        shutil.copy2('/etc/sysconfig/ip6tables', '/etc/sysconfig/ip6tables.bak')

    shellexec('ip6tables-save > /etc/sysconfig/ip6tables')

    yield None

    if os.path.exists('/etc/sysconfig/ip6tables.bak'):
        shutil.move('/etc/sysconfig/ip6tables.bak', '/etc/sysconfig/ip6tables')
    else:
        os.remove('/etc/sysconfig/ip6tables.bak')


@pytest.fixture
def setup_to_fail_ipv4():
    if os.path.exists('/etc/sysconfig/iptables'):
        shutil.move('/etc/sysconfig/iptables', '/etc/sysconfig/iptables.bak')

    yield None

    if os.path.exists('/etc/sysconfig/iptables.bak'):
        shutil.move('/etc/sysconfig/iptables.bak', '/etc/sysconfig/iptables')


@pytest.fixture
def setup_to_fail_ipv6():
    if os.path.exists('/etc/sysconfig/ip6tables'):
        shutil.move('/etc/sysconfig/ip6tables', '/etc/sysconfig/ip6tables.bak')

    yield None

    if os.path.exists('/etc/sysconfig/ip6tables.bak'):
        shutil.move('/etc/sysconfig/ip6tables.bak', '/etc/sysconfig/ip6tables')


## IPv4
def test_integration_audit_iptables_rules_are_saved_pass_ipv4(setup_to_pass_ipv4):
    state = CISAudit().audit_iptables_rules_are_saved(ip_version='ipv4')
    assert state == 0


def test_integration_audit_iptables_rules_are_saved_fail_ipv4(setup_to_fail_ipv4):
    state = CISAudit().audit_iptables_rules_are_saved(ip_version='ipv4')
    assert state == 1


## IPv6
def test_integration_audit_iptables_rules_are_saved_pass_ipv6(setup_to_pass_ipv6):
    state = CISAudit().audit_iptables_rules_are_saved(ip_version='ipv6')
    assert state == 0


def test_integration_audit_iptables_rules_are_saved_fail_ipv6(setup_to_fail_ipv6):
    state = CISAudit().audit_iptables_rules_are_saved(ip_version='ipv6')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
