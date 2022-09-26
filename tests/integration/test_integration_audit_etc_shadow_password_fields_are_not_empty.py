#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_fail():
    shellexec('echo "pytest::18353:0:99999:7:::" >> /etc/shadow')

    yield None

    shellexec('sed -i "/pytest/d" /etc/shadow')


def test_integration_audit_etc_shadow_password_fields_are_not_empty_pass():
    state = CISAudit().audit_etc_shadow_password_fields_are_not_empty()
    assert state == 0


def test_integration_audit_etc_shadow_password_fields_are_not_empty_fail(setup_to_fail):
    state = CISAudit().audit_etc_shadow_password_fields_are_not_empty()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
