#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from unittest.mock import patch
from types import SimpleNamespace

test = CISAudit()


def mock_default_group_for_root_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['0']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_default_group_for_root_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['1']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_default_group_for_root_pass)
def test_audit_default_group_for_root_pass():
    state = test.audit_default_group_for_root()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_default_group_for_root_fail)
def test_audit_default_group_for_root_fail():
    state = test.audit_default_group_for_root()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
