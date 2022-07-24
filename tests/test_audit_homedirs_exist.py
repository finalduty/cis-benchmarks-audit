#!/usr/bin/env python3

## Tests in this file use pyfakefs to fake the filesystem the homedirs are created in. This provides the 'fs' fixture.
## Refer to https://jmcgeheeiv.github.io/pyfakefs/release/usage.html#patch-using-the-pytest-plugin

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cis_audit import CISAudit


def mock_homedirs_data(self, cmd):
    output = [
        '/root/',
        '/home/pytest',
        '',
    ]
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_exist_fail_all(fs):
    state = test.audit_homedirs_exist()
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_exist_fail_one(fs):
    fs.create_dir('/root')

    state = test.audit_homedirs_exist()
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_exist_pass(fs):
    fs.create_dir('/root')
    fs.create_dir('/home/pytest')

    state = test.audit_homedirs_exist()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
