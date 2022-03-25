#!/usr/bin/env python3

#!/usrbin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_sticky_bit_set(self, cmd):
    output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sticky_bit_not_set(self, cmd):
    output = ['/pytest']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_sticky_bit_error(self, cmd):
    output = ['']
    error = ['find: invalid expression; I was expecting to find a \')\' somewhere but did not see one.']
    returncode = 123

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestPartitionOptions:
    test = CISAudit()
    test_id = '1.1'

    @patch.object(CISAudit, "_shellexec", mock_sticky_bit_set)
    def test_directory_sticky_bit_is_set(self):
        state = self.test.audit_sticky_bit_on_world_writable_dirs()
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_sticky_bit_not_set)
    def test_directory_sticky_bit_is_not_set(self):
        state = self.test.audit_sticky_bit_on_world_writable_dirs()
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
