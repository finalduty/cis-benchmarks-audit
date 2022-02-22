#!/usr/bin/env python3

from cis_audit import CISAudit


def test_manually():
    test = CISAudit()
    result = test.manually('1.1')

    assert result == 'Manual'
