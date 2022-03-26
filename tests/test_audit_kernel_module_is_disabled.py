#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import CISAudit


def mock_module_disabled(self, cmd):
    if 'modprobe' in cmd:
        output = ['install /bin/true\n']
        error = ['']
        returncode = 0
    elif 'lsmod' in cmd:
        output = ['']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_module_enabled(self, cmd):
    if 'modprobe' in cmd:
        output = ['insmod /lib/modules/3.10.0-1160.45.1.el7.x86_64/kernel/fs/fat/fat.ko.xz\ninsmod /lib/modules/3.10.0-1160.45.1.el7.x86_64/kernel/fs/fat/vfat.ko.xz\n']
        error = ['']
        returncode = 0
    elif 'lsmod' in cmd:
        output = ['pytest                  584133  2']
        error = ['']
        returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_not_found(self, cmd):
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
    test = CISAudit()
    module = 'pytest'

    @patch.object(CISAudit, "_shellexec", mock_module_disabled)
    def test_filesystem_disabled(self):
        state = self.test.audit_kernel_module_is_disabled(module=self.module)
        assert state == 0

    @patch.object(CISAudit, "_shellexec", mock_module_enabled)
    def test_filesystem_enabled(self):
        state = self.test.audit_kernel_module_is_disabled(module=self.module)
        assert state == 1

    @patch.object(CISAudit, "_shellexec", mock_filesystem_not_found)
    def test_filesystem_not_found(self):
        state = self.test.audit_kernel_module_is_disabled(module=self.module)
        assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
