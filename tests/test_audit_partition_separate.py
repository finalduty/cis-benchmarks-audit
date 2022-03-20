#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_parition_exists(self, cmd):
    output = ['/dev/sda1            1014M  125M  890M  13% /boot']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_parititon_not_exists(self, cmd):
    output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionSeparate:
    test_id = '1.1'
    test_level = 1
    partition = '/dev/sda1'
    test = CISAudit()

    @patch.object(CISAudit, "_shellexec", mock_parition_exists)
    def test_partition_is_separate(self):
        state = self.test.audit_partition_is_separate(partition=self.partition)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_parititon_not_exists)
    def test_partition_is_not_separate(self):
        state = self.test.audit_partition_is_separate(partition=self.partition)
        assert state == 1

if __name__ == '__main__':
    pytest.main([__file__])
