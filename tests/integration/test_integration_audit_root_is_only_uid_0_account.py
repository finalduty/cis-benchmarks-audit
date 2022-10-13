#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    shutil.copy('/etc/passwd', '/etc/passwd.bak')
    shellexec('echo "pytest:x:0:0:PyTest:/home/pytest:/bin/bash" >> /etc/passwd')

    yield None

    ## Tear-down
    shutil.move('/etc/passwd.bak', '/etc/passwd')


def test_integration_audit_root_is_only_uid_0_account_pass():
    state = CISAudit().audit_root_is_only_uid_0_account()
    assert state == 0


def test_integration_audit_root_is_only_uid_0_account_fail(setup_to_fail):
    state = CISAudit().audit_root_is_only_uid_0_account()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
