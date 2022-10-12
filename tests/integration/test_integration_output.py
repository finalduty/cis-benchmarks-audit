#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

data = [
    ('1', 'section header'),
    ('1.1', 'subsection header'),
    ('1.1.1', 'test 1.1.1', 1, 'Pass', '1ms'),
    ('2', 'section header'),
    ('2.1', 'test 2.1', 1, 'Fail', '10ms'),
    ('2.2', 'test 2.2', 2, 'Pass', '100ms'),
    ('2.3', 'test 2.3', 1, 'Not Implemented'),
]


test = CISAudit()


def test_integration_output_csv(capsys):
    CISAudit().output(data=data, format='csv')

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'ID,Description,Level,Result,Duration'
    assert output.split('\n')[1] == '1,"section header",,,'
    assert output.split('\n')[2] == '1.1,"subsection header",,,'
    assert output.split('\n')[3] == '1.1.1,"test 1.1.1",1,Pass,1ms'
    assert output.split('\n')[4] == '2,"section header",,,'
    assert output.split('\n')[5] == '2.1,"test 2.1",1,Fail,10ms'
    assert output.split('\n')[6] == '2.2,"test 2.2",2,Pass,100ms'
    assert output.split('\n')[7] == '2.3,"test 2.3",1,Not Implemented,'


def test_integration_output_json(capsys):
    CISAudit().output(data=data, format='json')

    output, error = capsys.readouterr()
    assert error == ''
    assert output == '{"1": {"description": "section header"}, "1.1": {"description": "subsection header"}, "1.1.1": {"description": "test 1.1.1", "level": 1, "result": "Pass", "duration": "1ms"}, "2": {"description": "section header"}, "2.1": {"description": "test 2.1", "level": 1, "result": "Fail", "duration": "10ms"}, "2.2": {"description": "test 2.2", "level": 2, "result": "Pass", "duration": "100ms"}, "2.3": {"description": "test 2.3", "level": 1, "result": "Not Implemented"}}\n'


def test_integration_output_psv(capsys):
    CISAudit().output(data=data, format='psv')

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'ID|Description|Level|Result|Duration'
    assert output.split('\n')[1] == '1|"section header"|||'
    assert output.split('\n')[2] == '1.1|"subsection header"|||'
    assert output.split('\n')[3] == '1.1.1|"test 1.1.1"|1|Pass|1ms'
    assert output.split('\n')[4] == '2|"section header"|||'
    assert output.split('\n')[5] == '2.1|"test 2.1"|1|Fail|10ms'
    assert output.split('\n')[6] == '2.2|"test 2.2"|2|Pass|100ms'
    assert output.split('\n')[7] == '2.3|"test 2.3"|1|Not Implemented|'


def test_integration_output_text(capsys):
    CISAudit().output(data=data, format='text')

    output, error = capsys.readouterr()
    print(output)

    assert error == ''
    assert output.split('\n')[0] == "ID     Description        Level      Result       Duration"
    assert output.split('\n')[1] == "-----  -----------------  -----  ---------------  --------"
    assert output.split('\n')[2] == ""
    assert output.split('\n')[3] == "1      section header                                     "
    assert output.split('\n')[4] == "1.1    subsection header                                  "
    assert output.split('\n')[5] == "1.1.1  test 1.1.1           1         Pass             1ms"
    assert output.split('\n')[6] == ""
    assert output.split('\n')[7] == "2      section header                                     "
    assert output.split('\n')[8] == "2.1    test 2.1             1         Fail            10ms"
    assert output.split('\n')[9] == "2.2    test 2.2             2         Pass           100ms"
    assert output.split('\n')[10] == "2.3    test 2.3             1    Not Implemented          "


def test_integration_output_tsv(capsys):
    CISAudit().output(data=data, format='tsv')

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'ID	Description	Level	Result	Duration'
    assert output.split('\n')[1] == '1	"section header"			'
    assert output.split('\n')[2] == '1.1	"subsection header"			'
    assert output.split('\n')[3] == '1.1.1	"test 1.1.1"	1	Pass	1ms'
    assert output.split('\n')[4] == '2	"section header"			'
    assert output.split('\n')[5] == '2.1	"test 2.1"	1	Fail	10ms'
    assert output.split('\n')[6] == '2.2	"test 2.2"	2	Pass	100ms'
    assert output.split('\n')[7] == '2.3	"test 2.3"	1	Not Implemented	'


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
