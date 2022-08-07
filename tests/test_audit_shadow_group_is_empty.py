#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_shadow_group_is_empty(self, cmd):
    output = ['', '']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_shadow_group_is_not_empty(self, cmd):
    output = ['user', '']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_shadow_group_is_absent(self, cmd):
    output = ['']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_shadow_group_is_empty)
def test_shadow_group_is_empty_pass():
    state = test.audit_shadow_group_is_empty()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_shadow_group_is_absent)
def test_shadow_group_is_absent_pass():
    state = test.audit_shadow_group_is_empty()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_shadow_group_is_not_empty)
def test_shadow_group_is_empty_fail():
    state = test.audit_shadow_group_is_empty()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
