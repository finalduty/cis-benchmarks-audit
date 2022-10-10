#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit


def test_integration_audit_partition_option_is_set():
    state = CISAudit().audit_partition_option_is_set(partition='/boot', option='relatime')
    assert state == 0


def test_integration_audit_partition_option_is_not_set():
    state = CISAudit().audit_partition_option_is_set(partition='/boot', option='nodev')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
