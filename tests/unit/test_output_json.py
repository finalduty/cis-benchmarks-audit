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
    'total': 9,
    'duration': 20,
}


def test_output_json(capsys):
    CISAudit().output_json(results=results, host_os=host_os, benchmark_version=benchmark_version, stats=stats)

    output, error = capsys.readouterr()
    assert error == ''
    print(output)
    assert output == '{"metadata": {"passed": 5, "failed": 3, "skipped": 2, "errors": 1, "total": 9, "duration": 20, "host_os": "CentOS 7", "benchmark_version": "3.1.2"}, "results": [{"_id": "1", "description": "section header"}, {"_id": "1.1", "description": "subsection header"}, {"_id": "1.1.1", "description": "test 1.1.1", "level": 1, "result": "Pass", "duration": "1ms"}, {"_id": "2", "description": "section header"}, {"_id": "2.1", "description": "test 2.1", "level": 1, "result": "Fail", "duration": "10ms"}, {"_id": "2.2", "description": "test 2.2", "level": 2, "result": "Pass", "duration": "100ms"}, {"_id": "2.3", "description": "test 2.3", "level": 1, "result": "Not Implemented"}]}\n'


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
