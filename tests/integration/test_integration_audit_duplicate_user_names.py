#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('echo "pytest:x:1001:1001:pytest:/bin/bash" >> /etc/passwd')
    shellexec('echo "pytest:x:1002:1002:pytest:/bin/bash" >> /etc/passwd')

    yield None

    shellexec('sed -i "/pytest/d" /etc/passwd')


def test_integration_audit_duplicate_user_names_pass():
    state = CISAudit().audit_duplicate_user_names()
    assert state == 0


def test_integration_audit_duplicate_user_names_fail(setup_to_fail):
    state = CISAudit().audit_duplicate_user_names()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
