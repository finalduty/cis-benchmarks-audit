#!/usr/bin/env python3

from cis_audit import CISAudit


def test_header():
    test_id = '1'
    result = CISAudit().header(test_id)

    assert result == 'Header'
