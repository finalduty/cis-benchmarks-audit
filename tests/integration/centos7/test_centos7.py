#!/usr/bin/env python3

import subprocess
import pytest


def test_centos7_vagrant():
    result = subprocess.run('w', universal_newlines=True)

    assert result.returncode == 0
    assert result.stdout != ''
    # assert result.stderr == ''


def test_centos7_vagrant_ls():
    result = subprocess.run(['ls', '-hal'], universal_newlines=True)

    assert result.returncode == 0
    assert result.stdout != ''
    # assert result.stderr == ''


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-v'])
