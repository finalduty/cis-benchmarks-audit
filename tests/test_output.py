#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit


def test_output(capsys):
    results = [['foo', 'bar'], ['zip', 'zap']]

    CISAudit().output(results)

    output, error = capsys.readouterr()
    assert output.split('\n')[0] == "['foo', 'bar']"
    assert output.split('\n')[1] == "['zip', 'zap']"


if __name__ == '__main__':
    pytest.main([__file__])
