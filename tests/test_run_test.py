#!/usr/bin/env python3

from cis_audit import CISAudit


def true(test_id, **kwargs):
    return True


def false(test_id, **kwargs):
    return False


def none(test_id, **kwargs):
    return None


def test_run_test_true():
    test = CISAudit()
    test_id = '1.1'
    test_level = 1
    test_function = true

    result = test.run_test(test_id, test_level, test_function)

    assert result is True


def test_run_test_false():
    test = CISAudit()
    test_id = '1.1'
    test_level = 1
    test_function = false

    result = test.run_test(test_id, test_level, test_function)

    assert result is False


def test_run_test_none():
    test = CISAudit()
    test_id = '1.1'
    test_level = 1
    test_function = none

    result = test.run_test(test_id, test_level, test_function)

    assert result is None
