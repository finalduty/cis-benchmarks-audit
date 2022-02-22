#!/usrbin/env python3

import cis_audit
from types import SimpleNamespace
from unittest.mock import patch


def mock_option_set(cmd):
    output = ['xfs on /pytest type proc (rw,nosuid,nodev,noexec,relatime)']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_option_not_set(cmd):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionOptions:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_level = 1
    partition = '/pytest'
    option = 'noexec'

    @patch.object(cis_audit, "shellexec", mock_option_set)
    def test_partition_option_is_set(self):
        result = self.test.audit_partition_option_is_set(self.test_id, partition=self.partition, option=self.option)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_option_not_set)
    def test_partition_option_is_not_set(self):
        result = self.test.audit_partition_option_is_set(self.test_id, partition=self.partition, option=self.option)

        assert result == 'Fail'
