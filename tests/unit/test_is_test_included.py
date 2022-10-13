#!/usr/bin/env python3
## andy.dustin@gmail.com [rev: 83422a0e]

from types import SimpleNamespace

import pytest

from cis_audit import CISAudit


def test_id_included(caplog):
    """Test that an ID which has been included returns True"""
    test_id = '1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=['1.1'], excludes=None, level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id, test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Test {test_id} was explicitly included'
    assert caplog.records[2].msg == f'Including test {test_id}'
    assert len(caplog.records) == 3
    assert result is True


def test_id_not_included(caplog):
    """Test that an ID which isn't explicitly included returns False"""
    test_id = '1.2'
    test_level = 1
    custom_config = SimpleNamespace(includes=['1.1'], excludes=None, level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id, test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Excluding test {test_id} (Not found in the include list)'
    assert caplog.records[2].msg == f'Not including test {test_id}'
    assert len(caplog.records) == 3
    assert result is False


def test_id_excluded(caplog):
    """Test that an ID which is explicitly excluded returns False"""
    test_id = '1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=None, excludes=['1.1'], level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id, test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Test {test_id} was explicitly excluded'
    assert caplog.records[2].msg == f'Not including test {test_id}'
    assert len(caplog.records) == 3
    assert result is False


def test_id_not_excluded(caplog):
    """Test that an ID which is not excluded returns True"""
    test_id = '1.2'
    test_level = 1
    custom_config = SimpleNamespace(includes=None, excludes=['1.1'], level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Including test {test_id}'
    assert result is True


def test_parent_id_included(caplog):
    """Test that an ID whose parent has been included returns True"""
    test_id = '1.1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=['1.1'], excludes=None, level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Test {test_id} is the child of an included test'
    assert caplog.records[2].msg == f'Including test {test_id}'
    assert len(caplog.records) == 3
    assert result is True


def test_child_id_included(caplog):
    """Test that an ID whose child has been included returns True"""
    test_id = '1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=['1.1.1'], excludes=None, level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Test {test_id} is the parent of an included test'
    assert caplog.records[2].msg == f'Including test {test_id}'
    assert len(caplog.records) == 3
    assert result is True


def test_parent_id_excluded(caplog):
    """Test that an ID whose parent has been excluded returns False"""
    test_id = '1.1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=None, excludes=['1.1'], level=0, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Test {test_id} is the child of an excluded test'
    assert caplog.records[2].msg == f'Not including test {test_id}'
    assert len(caplog.records) == 3
    assert result is False


def test_level_matches_testing_level(caplog):
    """Test that a test's level which matches the testing level returns True"""
    test_id = '1.1'
    test_level = 1
    custom_config = SimpleNamespace(includes=None, excludes=None, level=1, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Including test {test_id}'
    assert len(caplog.records) == 2
    assert result is True


def test_level_not_matches_testing_level(caplog):
    """Test that a test's level which doesn't match the testing level returns False"""
    test_id = '1.1'
    test_level = 2
    custom_config = SimpleNamespace(includes=None, excludes=None, level=1, log_level='DEBUG')
    test = CISAudit(config=custom_config)

    result = test._is_test_included(test_id=test_id, test_level=test_level)

    assert caplog.records[0].msg == f'Checking whether to run test {test_id}'
    assert caplog.records[1].msg == f'Excluding level {test_level} test {test_id}'
    assert caplog.records[2].msg == f'Not including test {test_id}'
    assert len(caplog.records) == 3
    assert result is False


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
