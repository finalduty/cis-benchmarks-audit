#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

test = CISAudit()

test_list = [
    {'_id': "1", 'description': "Initial Setup", 'type': "header"},
    {'_id': "1.1", 'description': "Filesystem Configuration", 'type': "header"},
    {'_id': "1.1.1", 'description': "Disable unused filesystems", 'type': "header"},
    {'_id': "1.1.1.1", 'description': "Ensure mounting of cramfs is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'cramfs'}, 'levels': {'server': 1, 'workstation': 1}},
    {'_id': "1.1.1.2", 'description': "Ensure mounting of squashfs is disabled", 'type': "skip", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'squashfs'}, 'levels': {'server': 2, 'workstation': 2}},
    {'_id': "1.1.1.3", 'description': "Ensure mounting of udf is disabled", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
    {'_id': "1.1.22", 'description': 'Ensure sticky bit is set on all world-writable directories', 'function': CISAudit.audit_sticky_bit_on_world_writable_dirs, 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
    {'_id': "1.2.3", 'description': "Ensure gpgcheck is globally activated", 'function': CISAudit.audit_gpgcheck_is_activated, 'levels': {'server': 1, 'workstation': 1}},
    {'_id': "1.8.3", 'description': "Ensure last logged in user display is disabled", 'function': CISAudit.audit_gdm_last_user_logged_in_disabled, 'levels': {'server': 1, 'workstation': 1}},
    {'_id': "9.9.9", 'description': "Test error", 'function': CISAudit().audit_file_permissions(file='/tmp/pytest', expected_mode='0644', expected_user='root', expected_group='root'), 'levels': {'server': 1, 'workstation': 1}},
]


def test_integration_run_tests(capsys, caplog):
    results = CISAudit().run_tests(tests=test_list)

    print(results)
    assert caplog.records != ''
    assert results[0] == ('1', 'Initial Setup')
    assert results[1] == ('1.1', 'Filesystem Configuration')
    assert results[2] == ('1.1.1', 'Disable unused filesystems')
    assert results[3] == ('1.1.1.1', 'Ensure mounting of cramfs is disabled', 1, 'Fail', results[3][4])
    assert results[4] == ('1.1.1.2', 'Ensure mounting of squashfs is disabled', 2, 'Skipped')
    assert results[5] == ('1.1.1.3', 'Ensure mounting of udf is disabled', 1, 'Not Implemented')
    assert results[6] == ('1.1.22', 'Ensure sticky bit is set on all world-writable directories', 1, 'Manual')
    assert results[7] == ('1.2.3', 'Ensure gpgcheck is globally activated', 1, 'Pass', results[7][4])
    assert results[8] == ('1.8.3', 'Ensure last logged in user display is disabled', 1, 'Skipped', results[8][4])
    assert results[9] == ('9.9.9', 'Test error', 1, 'Error', results[9][4])


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
