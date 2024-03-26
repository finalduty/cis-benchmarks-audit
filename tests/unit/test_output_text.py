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
stats = {
    'passed': 5,
    'failed': 3,
    'skipped': 2,
    'errors': 1,
    'duration': 20,
    'total': 9,
}


def test_output_text(capsys):
    CISAudit().output_text(results=results, host_os=host_os, benchmark_version=benchmark_version, stats=stats)

    output, error = capsys.readouterr()
    print(output)

    assert error == ''
    assert output.split('\n')[0] == "CIS CentOS 7 Benchmark v3.1.2 Results"
    assert output.split('\n')[1] == "-------------------------------------"
    assert output.split('\n')[2] == "ID     Description        Level      Result       Duration"
    assert output.split('\n')[3] == "-----  -----------------  -----  ---------------  --------"
    assert output.split('\n')[4] == ""
    assert output.split('\n')[5] == "1      section header                                     "
    assert output.split('\n')[6] == "1.1    subsection header                                  "
    assert output.split('\n')[7] == "1.1.1  test 1.1.1           1         Pass             1ms"
    assert output.split('\n')[8] == ""
    assert output.split('\n')[9] == "2      section header                                     "
    assert output.split('\n')[10] == "2.1    test 2.1             1         Fail            10ms"
    assert output.split('\n')[11] == "2.2    test 2.2             2         Pass           100ms"
    assert output.split('\n')[12] == "2.3    test 2.3             1    Not Implemented          "
    assert output.split('\n')[13] == ""
    assert output.split('\n')[14] == "Passed 5 of 9 tests in 20 seconds (2 Skipped, 1 Errors)"


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-v'])
