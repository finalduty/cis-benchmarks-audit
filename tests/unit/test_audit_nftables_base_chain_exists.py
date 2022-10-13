#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nftables_base_chains_exist_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = ['type filter hook input priority 0;']
    elif 'forward' in cmd:
        stdout = ['type filter hook forward priority 0;']
    elif 'output' in cmd:
        stdout = ['type filter hook output priority 0;']
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_base_chains_exist_fail_input(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = ['']
        returncode = 1
    elif 'forward' in cmd:
        stdout = ['type filter hook forward priority 0;']
    elif 'output' in cmd:
        stdout = ['type filter hook output priority 0;']
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_base_chains_exist_fail_forward(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = ['type filter hook input priority 0;']
    elif 'forward' in cmd:
        stdout = ['']
        returncode = 1
    elif 'output' in cmd:
        stdout = ['type filter hook output priority 0;']
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_base_chains_exist_fail_output(self, cmd):
    returncode = 0
    stderr = ['']

    if 'input' in cmd:
        stdout = ['type filter hook input priority 0;']
    elif 'forward' in cmd:
        stdout = ['type filter hook forward priority 0;']
    elif 'output' in cmd:
        stdout = ['']
        returncode = 1
    else:
        stdout = ['']
        returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_base_chains_exist_fail_all(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestNFTablesBaseChainsExist:
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_nftables_base_chains_exist_pass)
    def test_audit_nftables_base_chains_exist_pass(self):
        state = self.test.audit_nftables_base_chains_exist()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_nftables_base_chains_exist_fail_input)
    def test_audit_nftables_base_chains_exist_fail_input(self):
        state = self.test.audit_nftables_base_chains_exist()
        assert state == 1

    @patch.object(CISAudit, "_shellexec", mock_nftables_base_chains_exist_fail_forward)
    def test_audit_nftables_base_chains_exist_fail_forward(self):
        state = self.test.audit_nftables_base_chains_exist()
        assert state == 2

    @patch.object(CISAudit, "_shellexec", mock_nftables_base_chains_exist_fail_output)
    def test_audit_nftables_base_chains_exist_fail_output(self):
        state = self.test.audit_nftables_base_chains_exist()
        assert state == 4

    @patch.object(CISAudit, "_shellexec", mock_nftables_base_chains_exist_fail_all)
    def test_audit_nftables_base_chains_exist_fail_all(self):
        state = self.test.audit_nftables_base_chains_exist()
        assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
