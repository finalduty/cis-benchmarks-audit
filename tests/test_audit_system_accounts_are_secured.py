#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_system_accounts_are_secured(self, cmd):
    if 'UID_MIN' in cmd:
        output = ['1000', '']
    else:
        output = [
            'root:x:0:0:root:/root:/bin/bash',
            'sync:x:5:0:sync:/sbin:/bin/sync',
            'shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown',
            'halt:x:7:0:halt:/sbin:/sbin/halt',
            'nobody:x:99:99:Nobody:/:/sbin/nologin',
            'vagrant:x:1000:1000:vagrant:/home/vagrant:/bin/bash',
        ]
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_system_accounts_are_not_secured(self, cmd):
    if 'UID_MIN' in cmd:
        output = ['1000', '']
    else:
        output = [
            'nobody:x:99:99:Nobody:/:/bin/bash',
        ]
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


test = CISAudit()


@patch.object(CISAudit, "_shellexec", mock_system_accounts_are_secured)
def test_system_accounts_are_secured():
    state = test.audit_system_accounts_are_secured()
    assert state == 0


@patch.object(CISAudit, "_shellexec", mock_system_accounts_are_not_secured)
def test_system_accounts_are_not_secured():
    state = test.audit_system_accounts_are_secured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
