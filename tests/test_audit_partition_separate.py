#!/usr/bin/env python3

import cis_audit
from types import SimpleNamespace
from unittest.mock import patch


def mock_parition_exists(cmd):
    output = ['/dev/sda1            1014M  125M  890M  13% /boot']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_parititon_not_exists(cmd):
    output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionSeparate:
    test_id = '1.1'
    test_level = 1
    partition = '/dev/sda1'
    test = cis_audit.CISAudit()

    @patch.object(cis_audit, "shellexec", mock_parition_exists)
    def test_partition_is_separate(self):
        result = self.test.audit_partition_is_separate(self.test_id, partition=self.partition)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_parititon_not_exists)
    def test_partition_is_not_separate(self):
        result = self.test.audit_partition_is_separate(self.test_id, partition=self.partition)

        assert result == 'Fail'
