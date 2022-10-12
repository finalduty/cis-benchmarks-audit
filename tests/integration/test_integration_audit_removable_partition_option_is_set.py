#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

test = CISAudit()


def test_integration_audit_removable_partition_option_is_set_pass():
    state = test.audit_removable_partition_option_is_set(option='noexec')
    assert state == 0


# def test_integration_audit_removable_partition_option_is_set_fail():
#    state = test.audit_removable_partition_option_is_set(option='noexec')
#    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
