#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nftables_connections_are_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = [
            'ip protocol tcp ct state established accept',
            'ip protocol udp ct state established accept',
            'ip protocol icmp ct state established accept',
        ]
    elif 'output' in cmd:
        stdout = [
            'ip protocol tcp ct state established,related,new accept',
            'ip protocol udp ct state established,related,new accept',
            'ip protocol icmp ct state established,related,new accept',
        ]
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_connections_are_configured_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_nftables_connections_are_configured_pass)
def test_audit_nftables_connections_are_configured_pass():
    state = test.audit_nftables_outbound_and_established_connections()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_nftables_connections_are_configured_fail)
def test_audit_nftables_connections_are_configured_fail_all():
    state = test.audit_nftables_outbound_and_established_connections()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
