#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from unittest.mock import patch
from types import SimpleNamespace

test = CISAudit()


def mock_duplicate_group_names_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_duplicate_group_names_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['pytest']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_duplicate_group_names_pass)
def test_audit_duplicate_group_names_pass():
    state = test.audit_duplicate_group_names()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_duplicate_group_names_fail)
def test_audit_duplicate_group_names_fail():
    state = test.audit_duplicate_group_names()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__])
