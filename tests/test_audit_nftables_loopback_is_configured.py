#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nftables_loopback_is_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'accept' in cmd:
        stdout = ['iif "lo" accept']
    elif 'ip saddr' in cmd:
        stdout = ['ip saddr 127.0.0.0/8 counter packets 99 bytes 99 drop']
    elif 'ip6 saddr' in cmd:
        stdout = ['ip6 saddr ::1 counter packets 0 bytes 0 drop']
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_loopback_is_configured_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestNFTablesBaseChainsExist:
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_nftables_loopback_is_configured_pass)
    def test_audit_nftables_loopback_is_configured_pass(self):
        state = self.test.audit_nftables_loopback_is_configured()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_nftables_loopback_is_configured_fail)
    def test_audit_nftables_loopback_is_configured_fail_all(self):
        state = self.test.audit_nftables_loopback_is_configured()
        assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
