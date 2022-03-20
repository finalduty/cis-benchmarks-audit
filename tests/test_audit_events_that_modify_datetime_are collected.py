#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit

test = CISAudit()


def mock_audit_events_that_modify_datetime_are_collected_pass(self, cmd):
    stdout = [
        '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change',
        '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        '-a always,exit -F arch=b32 -S clock_settime -k time-change',
        '-w /etc/localtime -p wa -k time-change',
        '',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_that_modify_datetime_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(CISAudit, "_shellexec", mock_audit_events_that_modify_datetime_are_collected_pass)
def test_audit_events_that_modify_datetime_are_collected_pass():
    state = test.audit_events_that_modify_datetime_are_collected()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_audit_events_that_modify_datetime_are_collected_fail)
def test_audit_events_that_modify_datetime_are_collected_fail():
    state = test.audit_events_that_modify_datetime_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__])
