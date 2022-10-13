#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit


@pytest.fixture
def setup_to_fail():
    ## Setup
    # We have to update the umask first, otherwise the directory is only created with 755 permissions
    os.umask(0o000)
    os.mkdir('/tmp/pytest', 0o777)

    yield None

    ## Tear-down
    os.rmdir('/tmp/pytest')


def test_integration_audit_sticky_bit_on_world_writable_dirs_pass():
    state = CISAudit().audit_sticky_bit_on_world_writable_dirs()
    assert state == 0


def test_integration_audit_sticky_bit_on_world_writable_dirs_fail(setup_to_fail):
    state = CISAudit().audit_sticky_bit_on_world_writable_dirs()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
