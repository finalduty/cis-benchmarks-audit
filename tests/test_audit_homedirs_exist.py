#!/usr/bin/env python3

## Tests in this file use pyfakefs to fake elements of the filesystem in order to perform the tests.
##   pyfakefs provides the 'fs' fixture automatically, but this is redefined to make it easier to understand
##   for people not familiar with it.
## Refer to https://jmcgeheeiv.github.io/pyfakefs/release/usage.html#patch-using-the-pytest-plugin
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.FakeFilesystem.create_dir
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.set_uid

from pyfakefs import fake_filesystem
from unittest.mock import patch

import pytest
from cis_audit import CISAudit


def mock_homedirs_data(self):
    data = [
        'root 0 /root',
        'pytest 1000 /home/pytest',
    ]

    for row in data:
        user, uid, homedir = row.split(' ')

        yield user, int(uid), homedir


## I know that pyfakefs automatically creates the 'fs' fixture for pytest for us, however stating it
##   explicitly helps demonstrate where it's come from for those less familar with it.
fs = fake_filesystem.FakeFilesystem()
test = CISAudit()


@patch.object(CISAudit, "_get_homedirs", mock_homedirs_data)
def test_audit_homedirs_exist_fail_all(fs):
    state = test.audit_homedirs_exist()
    assert state == 1


@patch.object(CISAudit, "_get_homedirs", mock_homedirs_data)
def test_audit_homedirs_exist_fail_one(fs):
    fs.create_dir('/root')

    state = test.audit_homedirs_exist()
    assert state == 1


@patch.object(CISAudit, "_get_homedirs", mock_homedirs_data)
def test_audit_homedirs_exist_pass(fs):
    fs.create_dir('/root')
    fs.create_dir('/home/pytest')

    state = test.audit_homedirs_exist()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
