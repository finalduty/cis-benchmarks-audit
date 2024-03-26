#!/usr/bin/env python3

import pytest
from mock import patch

from cis_audit import CISAudit

mock_data = [
    {'_id': '1', 'description': 'section header'},
]


def mock_output_function(self, results, separator=None, host_os=None, benchmark_version=None, stats=None):
    print(separator)
    print(results)


host_os = 'CentOS 7'
benchmark_version = '3.1.2'
stats = {
    'passed': 5,
    'failed': 3,
    'skipped': 2,
    'errors': 1,
    'duration': 20,
    'total': 9,
}

test = CISAudit()


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_csv_function(capfd):
    test.output(format='csv', results=mock_data, host_os=host_os, benchmark_version=benchmark_version, stats=stats)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == ','
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_psv_function(capfd):
    test.output(format='psv', results=mock_data, host_os=host_os, benchmark_version=benchmark_version, stats=stats)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == '|'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_tsv_function(capfd):
    test.output(format='tsv', results=mock_data, host_os=host_os, benchmark_version=benchmark_version, stats=stats)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == '\t'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_json', mock_output_function)
def test_output_calls_json_function(capfd):
    test.output(format='json', results=mock_data, host_os=host_os, benchmark_version=benchmark_version, stats=stats)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == 'None'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_text', mock_output_function)
def test_output_calls_text_function(capfd):
    test.output(format='text', results=mock_data, host_os=host_os, benchmark_version=benchmark_version, stats=stats)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == 'None'
    assert output[1] == str(mock_data)


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
