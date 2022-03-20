#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_iptables_default_deny_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INPUT' in cmd:
        stdout = ['-P INPUT DROP']
    elif 'FORWARD' in cmd:
        stdout = ['-P FORWARD DROP']
    elif 'OUTPUT' in cmd:
        stdout = ['-P OUTPUT DROP']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_default_deny_fail(self, cmd):
    stderr = ['']
    returncode = 1

    if 'INPUT' in cmd:
        stdout = ['-P INPUT ACCEPT']
    elif 'FORWARD' in cmd:
        stdout = ['-P FORWARD ACCEPT']
    elif 'OUTPUT' in cmd:
        stdout = ['-P OUTPUT ACCEPT']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_iptables_default_deny_pass)
def test_audit_iptables_default_deny_pass():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_default_deny_fail)
def test_audit_iptables_default_deny_fail():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 7


@patch.object(CISAudit, "_shellexec", mock_iptables_default_deny_pass)
def test_audit_ip6tables_default_deny_pass():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_default_deny_fail)
def test_audit_ip6tables_default_deny_fail():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__])
