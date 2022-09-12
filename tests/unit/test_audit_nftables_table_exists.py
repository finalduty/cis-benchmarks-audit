#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_nftables_table_exists_pass(self, cmd):
    stdout = ['table inet filter']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_nftables_table_exists_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestNFTablesTableExists:
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_nftables_table_exists_pass)
    def test_audit_nftables_table_exists_pass(self):
        state = self.test.audit_nftables_table_exists()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_nftables_table_exists_fail)
    def test_audit_nftables_table_exists_fail(self):
        state = self.test.audit_nftables_table_exists()
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
