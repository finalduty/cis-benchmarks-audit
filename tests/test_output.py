#!/usr/bin/env python3

from mock import patch
import pytest

from cis_audit import CISAudit

mock_data = [
    ('1', 'section header'),
]


def mock_output_function(self, data, separator=None):
    print(separator)
    print(data)


test = CISAudit()


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_csv_function(capfd):
    test.output(format='csv', data=mock_data)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == ','
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_psv_function(capfd):
    test.output(format='psv', data=mock_data)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == '|'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_csv', mock_output_function)
def test_output_calls_tsv_function(capfd):
    test.output(format='tsv', data=mock_data)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == '\t'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_json', mock_output_function)
def test_output_calls_json_function(capfd):
    test.output(format='json', data=mock_data)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == 'None'
    assert output[1] == str(mock_data)


@patch.object(CISAudit, 'output_text', mock_output_function)
def test_output_calls_text_function(capfd):
    test.output(format='text', data=mock_data)
    stdout, stderr = capfd.readouterr()

    output = stdout.split('\n')

    assert output[0] == 'None'
    assert output[1] == str(mock_data)


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
