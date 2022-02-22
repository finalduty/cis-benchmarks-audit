#!/usr/bin/env python3

from cis_audit import CISAudit


def test_skip():
    test = CISAudit()
    result = test.skip('1.1')

    assert result == 'Skip'
