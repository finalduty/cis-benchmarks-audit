#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_iptables_rules_are_saved_pass(self, cmd):
    stdout = [
        'COMMIT',
        '*filter',
        ':FORWARD ACCEPT ',
        ':INPUT ACCEPT ',
        ':OUTPUT ACCEPT ',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_rules_are_saved_fail_ipv4(self, cmd):
    if 'iptables-save' in cmd:
        stdout = [
            'COMMIT',
            '*filter',
            ':FORWARD ACCEPT ',
            ':INPUT ACCEPT ',
            ':OUTPUT ACCEPT ',
            '',
        ]
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_rules_are_saved_fail_ipv6(self, cmd):
    if 'ip6tables-save' in cmd:
        stdout = [
            'COMMIT',
            '*filter',
            ':FORWARD ACCEPT ',
            ':INPUT ACCEPT ',
            ':OUTPUT ACCEPT ',
            '',
        ]
    else:
        stdout = ['']

    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


## IPv4
@patch.object(CISAudit, "_shellexec", mock_iptables_rules_are_saved_pass)
def test_audit_iptables_rules_are_saved_pass():
    state = test.audit_iptables_rules_are_saved(ip_version='ipv4')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_rules_are_saved_fail_ipv4)
def test_audit_iptables_rules_are_saved_fail():
    state = test.audit_iptables_rules_are_saved(ip_version='ipv4')
    assert state == 1


## IPv6
@patch.object(CISAudit, "_shellexec", mock_iptables_rules_are_saved_pass)
def test_audit_ip6tables_rules_are_saved_pass():
    state = test.audit_iptables_rules_are_saved(ip_version='ipv6')
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_iptables_rules_are_saved_fail_ipv6)
def test_audit_ip6tables_rules_are_saved_fail():
    state = test.audit_iptables_rules_are_saved(ip_version='ipv6')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
