#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

results = [
    {'_id': '1', 'description': 'section header'},
    {'_id': '1.1', 'description': 'subsection header'},
    {'_id': '1.1.1', 'description': 'test 1.1.1', 'level': 1, 'result': 'Pass', 'duration': '1ms'},
    {'_id': '2', 'description': 'section header'},
    {'_id': '2.1', 'description': 'test 2.1', 'level': 1, 'result': 'Fail', 'duration': '10ms'},
    {'_id': '2.2', 'description': 'test 2.2', 'level': 2, 'result': 'Pass', 'duration': '100ms'},
    {'_id': '2.3', 'description': 'test 2.3', 'level': 1, 'result': 'Not Implemented'},
]

host_os = 'CentOS 7'
benchmark_version = '3.1.2'


def test_output_csv(capsys):
    CISAudit().output_csv(results=results, separator=',', host_os=host_os, benchmark_version=benchmark_version)

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'CIS CentOS 7 Benchmark v3.1.2 Results'
    assert output.split('\n')[1] == 'ID,Description,Level,Result,Duration'
    assert output.split('\n')[2] == '1,"section header",,,'
    assert output.split('\n')[3] == '1.1,"subsection header",,,'
    assert output.split('\n')[4] == '1.1.1,"test 1.1.1",1,Pass,1ms'
    assert output.split('\n')[5] == '2,"section header",,,'
    assert output.split('\n')[6] == '2.1,"test 2.1",1,Fail,10ms'
    assert output.split('\n')[7] == '2.2,"test 2.2",2,Pass,100ms'
    assert output.split('\n')[8] == '2.3,"test 2.3",1,Not Implemented,'


def test_output_psv(capsys):
    CISAudit().output_csv(results=results, separator='|', host_os=host_os, benchmark_version=benchmark_version)

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'CIS CentOS 7 Benchmark v3.1.2 Results'
    assert output.split('\n')[1] == 'ID|Description|Level|Result|Duration'
    assert output.split('\n')[2] == '1|"section header"|||'
    assert output.split('\n')[3] == '1.1|"subsection header"|||'
    assert output.split('\n')[4] == '1.1.1|"test 1.1.1"|1|Pass|1ms'
    assert output.split('\n')[5] == '2|"section header"|||'
    assert output.split('\n')[6] == '2.1|"test 2.1"|1|Fail|10ms'
    assert output.split('\n')[7] == '2.2|"test 2.2"|2|Pass|100ms'
    assert output.split('\n')[8] == '2.3|"test 2.3"|1|Not Implemented|'


def test_output_tsv(capsys):
    CISAudit().output_csv(results=results, separator='\t', host_os=host_os, benchmark_version=benchmark_version)

    output, error = capsys.readouterr()
    assert error == ''
    assert output.split('\n')[0] == 'CIS CentOS 7 Benchmark v3.1.2 Results'
    assert output.split('\n')[1] == 'ID	Description	Level	Result	Duration'
    assert output.split('\n')[2] == '1	"section header"			'
    assert output.split('\n')[3] == '1.1	"subsection header"			'
    assert output.split('\n')[4] == '1.1.1	"test 1.1.1"	1	Pass	1ms'
    assert output.split('\n')[5] == '2	"section header"			'
    assert output.split('\n')[6] == '2.1	"test 2.1"	1	Fail	10ms'
    assert output.split('\n')[7] == '2.2	"test 2.2"	2	Pass	100ms'
    assert output.split('\n')[8] == '2.3	"test 2.3"	1	Not Implemented	'


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
