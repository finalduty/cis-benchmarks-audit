#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit


def test_integration_audit_selinux_mode_not_disabled_pass_enforcing(setup_selinux_enforcing):
    state = CISAudit().audit_selinux_mode_not_disabled()
    assert state == 0


def test_integration_audit_selinux_mode_not_disabled_pass_permissive(setup_selinux_permissive):
    state = CISAudit().audit_selinux_mode_not_disabled()
    assert state == 0


def test_integration_audit_selinux_mode_not_disabled_fail_disabled(setup_selinux_disabled):
    state = CISAudit().audit_selinux_mode_not_disabled()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
