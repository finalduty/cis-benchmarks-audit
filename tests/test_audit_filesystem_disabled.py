#!/usr/bin/env python3

import cis_audit
from unittest.mock import patch
from types import SimpleNamespace


def mock_filesystem_disabled(cmd):
    if 'modprobe' in cmd:
        output = ['install /bin/true\n']
        error = ['']
        returncode = 0
    elif 'lsmod' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_enabled(cmd):
    if 'modprobe' in cmd:
        output = ['insmod /lib/modules/3.10.0-1160.45.1.el7.x86_64/kernel/fs/fat/fat.ko.xz\ninsmod /lib/modules/3.10.0-1160.45.1.el7.x86_64/kernel/fs/fat/vfat.ko.xz\n']
        error = ['']
        returncode = 0
    elif 'lsmod' in cmd:
        output = ['pytest                  584133  2']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_not_found(cmd):
    if 'modprobe' in cmd:
        output = ['']
        error = ['modprobe: FATAL: Module pytest not found.\n']
        returncode = 1
    elif 'lsmod' in cmd:
        output = ['']
        error = ['']
        returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestFilesystemDisabled:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    test_level = 1
    test_filesystems = ['pytest', 'pytest']

    @patch.object(cis_audit, "shellexec", mock_filesystem_disabled)
    def test_filesystem_disabled(self, caplog):
        result = self.test.audit_filesystem_is_disabled(self.test_id, filesystems=self.test_filesystems)

        assert result == 'Pass'
        assert caplog.records[0].msg == f'Test {self.test_id} finished with state 0'

    @patch.object(cis_audit, "shellexec", mock_filesystem_enabled)
    def test_filesystem_enabled(self, caplog):
        result = self.test.audit_filesystem_is_disabled(self.test_id, filesystems=self.test_filesystems)

        assert result == 'Fail'
        assert caplog.records[0].msg == f'Test {self.test_id} finished with state 1'

    @patch.object(cis_audit, "shellexec", mock_filesystem_not_found)
    def test_filesystem_not_found(self, caplog):
        result = self.test.audit_filesystem_is_disabled(self.test_id, filesystems=self.test_filesystems)

        assert result == 'Pass'
        assert caplog.records[0].msg == f'Test {self.test_id} finished with state 0'
