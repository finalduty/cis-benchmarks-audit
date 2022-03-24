#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

results = [
    ('1', 'section header'),
    ('1.1', 'subsection header'),
    ('1.1.1', 'test 1.1.1', 1, 'Pass', '1ms'),
    ('2', 'section header'),
    ('2.1', 'test 2.1', 1, 'Fail', '10ms'),
    ('2.2', 'test 2.2', 2, 'Pass', '100ms'),
    ('2.3', 'test 2.3', 1, 'Not Implemented'),
]


def test_csv_output(capsys):
    CISAudit().output(format='csv', data=results)

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == "1,section header,,,"
    assert output.split('\n')[1] == "1.1,subsection header,,,"
    assert output.split('\n')[2] == "1.1.1,test 1.1.1,1,Pass,1ms"
    assert output.split('\n')[3] == "2,section header,,,"
    assert output.split('\n')[4] == "2.1,test 2.1,1,Fail,10ms"
    assert output.split('\n')[5] == "2.2,test 2.2,2,Pass,100ms"
    assert output.split('\n')[6] == "2.3,test 2.3,1,Not Implemented,"


def test_json_output(capsys):
    CISAudit().output(format='json', data=results)

    output, error = capsys.readouterr()
    assert error == ''
    assert output == '{"1": {"description": "section header"}, "1.1": {"description": "subsection header"}, "1.1.1": {"description": "test 1.1.1", "level": 1, "result": "Pass", "duration": "1ms"}, "2": {"description": "section header"}, "2.1": {"description": "test 2.1", "level": 1, "result": "Fail", "duration": "10ms"}, "2.2": {"description": "test 2.2", "level": 2, "result": "Pass", "duration": "100ms"}, "2.3": {"description": "test 2.3", "level": 1, "result": "Not Implemented"}}\n'


def test_text_output(capsys):
    CISAudit().output(format='text', data=results)

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == "('1', 'section header')"
    assert output.split('\n')[1] == "('1.1', 'subsection header')"
    assert output.split('\n')[2] == "('1.1.1', 'test 1.1.1', 1, 'Pass', '1ms')"
    assert output.split('\n')[3] == "('2', 'section header')"
    assert output.split('\n')[4] == "('2.1', 'test 2.1', 1, 'Fail', '10ms')"
    assert output.split('\n')[5] == "('2.2', 'test 2.2', 2, 'Pass', '100ms')"
    assert output.split('\n')[6] == "('2.3', 'test 2.3', 1, 'Not Implemented')"


if __name__ == '__main__':
    pytest.main([__file__])
