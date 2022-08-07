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


def test_output_csv(capsys):
    CISAudit().output_csv(data=results, separator=',')

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


def test_output_psv(capsys):
    CISAudit().output_csv(data=results, separator='|')

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


def test_output_tsv(capsys):
    CISAudit().output_csv(data=results, separator='\t')

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
