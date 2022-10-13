#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit


def test_integration_audit_ervice_active_pass():
    state = CISAudit().audit_service_is_active(service='sshd')
    assert state == 0


def test_integration_audit_service_active_fail():
    state = CISAudit().audit_service_is_active(service='rsyncd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
