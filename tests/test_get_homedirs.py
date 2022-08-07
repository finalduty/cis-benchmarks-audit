#!/usr/bin/env python3

## Tests in this file use pyfakefs to fake elements of the filesystem in order to perform the tests.
##   pyfakefs provides the 'fs' fixture automatically, but this is redefined to make it easier to understand
##   for people not familiar with it.
## Refer to https://jmcgeheeiv.github.io/pyfakefs/release/usage.html#patch-using-the-pytest-plugin
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.FakeFilesystem.create_dir
##          https://jmcgeheeiv.github.io/pyfakefs/release/modules.html#pyfakefs.fake_filesystem.set_uid

from types import GeneratorType, SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_homedirs_data(self, cmd):
    stderr = []
    stdout = [
        'root 0 /root',
        'pytest 1000 /home/pytest',
    ]
    returncode = 0

    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_homedirs_data)
def test_get_homedirs_pass():
    homedirs = test._get_homedirs()
    homedirs_list = list(homedirs)

    assert isinstance(homedirs, GeneratorType)
    assert homedirs_list[0] == ('root', 0, '/root')
    assert homedirs_list[1] == ('pytest', 1000, '/home/pytest')


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
