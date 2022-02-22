#!/usrbin/env python3

import cis_audit
from types import SimpleNamespace
from unittest.mock import patch


def mock_sticky_bit_set(cmd):
    output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sticky_bit_not_set(cmd):
    output = ['/pytest']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sticky_bit_error(cmd):
    output = ['']
    error = ['find: invalid expression; I was expecting to find a \')\' somewhere but did not see one.']
    returncode = 123

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionOptions:
    test = cis_audit.CISAudit()
    test_id = '1.1'

    @patch.object(cis_audit, "shellexec", mock_sticky_bit_set)
    def test_directory_sticky_bit_is_set(self):
        result = self.test.audit_sticky_bit_on_world_writable_dirs(self.test_id)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_sticky_bit_not_set)
    def test_directory_sticky_bit_is_not_set(self):
        result = self.test.audit_sticky_bit_on_world_writable_dirs(self.test_id)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_sticky_bit_error)
    def test_directory_sticky_bit_error(self):
        result = self.test.audit_sticky_bit_on_world_writable_dirs(self.test_id)

        assert result == 'Error'
