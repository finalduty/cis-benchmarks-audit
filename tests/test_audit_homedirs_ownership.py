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
from cis_audit import CISAudit

from pyfakefs import fake_filesystem


def mock_homedirs_data(self, cmd):
    output = [
        'root 0 /root',
        'pytest 1000 /home/pytest',
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
def test_audit_users_own_their_own_homedir_fail(fs):
    ## Create /root and /home/pytest as root:root
    fake_filesystem.set_uid(0)
    fake_filesystem.set_gid(0)
    fs.create_dir('/root')
    fs.create_dir('/home/pytest')

    state = test.audit_homedirs_ownership()
    assert state == 1


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_audit_users_own_their_own_homedir_pass(fs):
    ## Create /root homedir as root:root
    fake_filesystem.set_uid(0)
    fake_filesystem.set_gid(0)
    fs.create_dir('/root')

    ## Create /home/pytest as pytest:pytest
    fake_filesystem.set_uid(1000)
    fake_filesystem.set_gid(1000)
    fs.create_dir('/home/pytest')

    state = test.audit_homedirs_ownership()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
