#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

test = CISAudit()


def test_shellexec_stdout_pass():
    result = test._shellexec('echo stdout')
    assert result.returncode == 0
    assert result.stdout[0] == 'stdout'
    assert result.stderr[0] == ''


def test_shellexec_sterr_pass():
    result = test._shellexec('echo stderr | tee /dev/stderr 1>/dev/null')
    assert result.returncode == 0
    assert result.stdout[0] == ''
    assert result.stderr[0] == 'stderr'


def test_shellexec_sterr_error():
    result = test._shellexec('error pytest')
    assert result.returncode == 127
    assert result.stderr[0] in ['/bin/sh: error: command not found', '/bin/sh: 1: error: not found']
    assert result.stdout[0] == ''


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
