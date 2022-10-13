#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_option_set(self, cmd):
    output = ['xfs on /pytest type proc (rw,nosuid,nodev,noexec,relatime)']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_option_not_set(self, cmd):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionOptions:
    test = CISAudit()
    test_id = '1.1'
    test_level = 1
    partition = '/pytest'
    option = 'noexec'

    @patch.object(CISAudit, "_shellexec", mock_option_set)
    def test_partition_option_is_set(self):
        state = self.test.audit_partition_option_is_set(partition=self.partition, option=self.option)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_option_not_set)
    def test_partition_option_is_not_set(self):
        state = self.test.audit_partition_option_is_set(partition=self.partition, option=self.option)
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
