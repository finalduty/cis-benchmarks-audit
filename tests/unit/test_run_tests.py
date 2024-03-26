#!/usr/bin/env python3

from datetime import datetime
from unittest.mock import patch

import pytest

import cis_audit


def mock_run_tests_pass(*args, **kwargs):
    return 0


def mock_run_tests_fail(*args, **kwargs):
    return 1


def mock_run_tests_error(*args, **kwargs):
    return -1


def mock_run_tests_skipped(*args, **kwargs):
    return -2


def mock_run_tests_kwargs(*args, **kwargs):
    return 0


def mock_run_tests_exception(*args, **kwargs):
    raise Exception


def mock_datetime_utcnow(offset=0):
    return datetime(year=1, month=1, day=1)


@patch.object(cis_audit.CISAudit, '_get_utcnow', mock_datetime_utcnow)
class TestRunTests:
    test = cis_audit.CISAudit()

    test_args = {}
    test_args['_id'] = '1.1'
    test_args['type'] = 'test'
    test_args['levels'] = {'server': 1, 'workstation': 1}
    test_args['description'] = 'pytest'

    def test_run_tests_pass(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_pass

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Pass', 'duration': '0ms'}]

    def test_run_tests_fail(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_fail

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Fail', 'duration': '0ms'}]

    def test_run_tests_error(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_error

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Error', 'duration': '0ms'}]

    def test_run_tests_exception(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_exception

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Error', 'duration': '0ms'}]

    def test_run_tests_skipped(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_skipped

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Skipped', 'duration': '0ms'}]

    def test_run_tests_kwargs(self):
        test_args = self.test_args.copy()
        test_args['function'] = mock_run_tests_kwargs
        test_args['kwargs'] = {'foo': 'bar'}
        test_args.pop('levels')

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': None, 'result': 'Pass', 'duration': '0ms'}]

    def test_run_tests_type_header(self):
        test_args = self.test_args.copy()
        test_args['type'] = 'header'

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description']}]

    def test_run_tests_type_manual(self):
        test_args = self.test_args.copy()
        test_args['type'] = 'manual'

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Manual'}]

    def test_run_tests_type_none(self, caplog):
        test_args = self.test_args.copy()
        test_args.pop('type', None)

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Not Implemented'}]
        assert caplog.records[0].msg == "Test 1.1 does not explicitly define a type, so assuming it is a test"
        assert caplog.records[1].msg == "Checking whether to run test 1.1"
        assert caplog.records[2].msg == "Including test 1.1"

    def test_run_tests_type_skip(self, caplog):
        test_args = self.test_args.copy()
        test_args['type'] = 'skip'

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Skipped'}]

    def test_run_tests_error_not_implemented(self, caplog):
        test_args = self.test_args.copy()
        test_args.pop('type')

        result = self.test.run_tests([test_args])
        assert result == [{'_id': test_args['_id'], 'description': test_args['description'], 'level': test_args['levels']['server'], 'result': 'Not Implemented'}]


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
