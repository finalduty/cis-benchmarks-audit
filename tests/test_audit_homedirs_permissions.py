#!/usr/bin/env python3

## Tests in this file use pyfakefs to fake elements of the filesystem in order to perform the tests.
##   pyfakefs provides the 'fs' fixture automatically, but this is redefined to make it easier to understand
##   for people not familiar with it.
## Refer to https://jmcgeheeiv.github.io/pyfakefs/release/usage.html#patch-using-the-pytest-plugin
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.FakeFilesystem.create_dir
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.set_uid

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pyfakefs import fake_filesystem

from cis_audit import CISAudit


def mock_homedirs_data(self, cmd):
    output = [
        '/root',
        '/home/pytest',
        '',
    ]
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


## I know that pyfakefs automatically creates the 'fs' fixture for pytest for us, however stating it
##   explicitly helps demonstrate where it's come from for those less familar with it.
fs = fake_filesystem.FakeFilesystem()
test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_permissions_pass_750(fs):
    fs.create_dir('/root', perm_bits=0o750)
    fs.create_dir('/home/pytest', perm_bits=0o750)

    state = test.audit_homedirs_permissions()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_permissions_pass_700(fs):
    fs.create_dir('/root', perm_bits=0o700)
    fs.create_dir('/home/pytest', perm_bits=0o700)

    state = test.audit_homedirs_permissions()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_permissions_fail_755(fs):
    fs.create_dir('/root', perm_bits=0o755)
    fs.create_dir('/home/pytest', perm_bits=0o755)

    state = test.audit_homedirs_permissions()
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_homedirs_permissions_fail_770(fs):
    fs.create_dir('/root', perm_bits=0o770)
    fs.create_dir('/home/pytest', perm_bits=0o770)

    state = test.audit_homedirs_permissions()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
