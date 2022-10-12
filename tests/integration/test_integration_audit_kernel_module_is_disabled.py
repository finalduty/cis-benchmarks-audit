#!/usr/bin/env python3

import os

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shellexec('echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf')

    yield None

    os.remove('/etc/modprobe.d/cramfs.conf')


@pytest.fixture
def setup_to_fail():
    print(shellexec('modprobe -v cramfs'))

    yield None

    print(shellexec('rmmod cramfs'))


def test_integration_audit_kernel_module_is_disabled_pass_disabled(setup_to_pass):
    state = CISAudit().audit_kernel_module_is_disabled(module='cramfs')
    assert state == 0


def test_integration_audit_kernel_module_is_disabled_pass_not_found():
    state = CISAudit().audit_kernel_module_is_disabled(module='pytest')
    assert state == 0


def test_integration_audit_kernel_module_is_disabled_fail(setup_to_fail):
    state = CISAudit().audit_kernel_module_is_disabled(module='cramfs')
    assert state == 2


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
