#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_duplicate_user_names_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_duplicate_user_names_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['pytest']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_duplicate_user_names_pass)
def test_audit_duplicate_user_names_pass():
    state = test.audit_duplicate_user_names()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_duplicate_user_names_fail)
def test_audit_duplicate_user_names_fail():
    state = test.audit_duplicate_user_names()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
