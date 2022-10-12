#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit

# from tests.integration import shellexec


@pytest.fixture
def setup_to_fail():
    ## Setup
    with open('/usr/local/sbin/dmesg', 'w') as f:
        f.writelines(
            {
                '/bin/dmesg | grep -v "Execute Disable',
            }
        )
    os.chmod('/usr/local/sbin/dmesg', 755)

    yield None

    ## Tear-down
    os.remove('/usr/local/sbin/dmesg')


def test_integration_audit_nxdx_support_enabled_pass():
    state = CISAudit().audit_nxdx_support_enabled()
    assert state == 0


def test_integration_audit_nxdx_support_enabled_fail(setup_to_fail):
    state = CISAudit().audit_nxdx_support_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
