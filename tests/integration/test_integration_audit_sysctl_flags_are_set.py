#!/usr/bin/env python3

import os
import pytest

from cis_audit import CISAudit

sysctl_flags = [
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
]


@pytest.fixture
def setup_to_pass():
    ## Setup
    with open('/etc/sysctl.d/pytest.conf', 'w') as f:
        f.writelines(
            [
                'net.ipv6.conf.all.disable_ipv6 = 0\n',
                'net.ipv6.conf.default.disable_ipv6 = 0\n',
            ]
        )

    yield None

    ## Tear-down
    os.remove('/etc/sysctl.d/pytest.conf')


def test_integration_audit_sysctl_flags_are_set_pass(setup_to_pass):
    state = CISAudit().audit_sysctl_flags_are_set(flags=sysctl_flags, value=0)
    assert state == 0


def test_integration_audit_sysctl_flags_are_set_fail():
    state = CISAudit().audit_sysctl_flags_are_set(flags=sysctl_flags, value=1)
    assert state == 15


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
