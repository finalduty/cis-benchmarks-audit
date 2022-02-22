#!/usr/bin/env python3

from types import SimpleNamespace
import cis_audit
from unittest.mock import patch


def mock_filesystem_integrity_pass_cron(cmd):
    output = ['/etc/cron.d/aide-check']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_pass_systemd(cmd):
    if 'is-enabled' in cmd:
        output = ['enabled']
        error = ['']
        returncode = 0
    elif 'is-active' in cmd:
        output = ['active']
        error = ['']
        returncode = 0
    else:
        output = ['']
        error = ['']
        returncode = 1
    
    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_fail(cmd):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_error(cmd):
    raise Exception


class TestFilesystemIntegrityRegularlyChecked:
    test = cis_audit.CISAudit()
    test_id = '1.1'

    @patch.object(cis_audit, "shellexec", mock_filesystem_integrity_pass_cron)
    def test_filesystem_integrity_pass_crond(self):
        result = self.test.audit_filesystem_integrity_regularly_checked(self.test_id)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_filesystem_integrity_pass_systemd)
    def test_filesystem_integrity_pass_systemd(self):
        result = self.test.audit_filesystem_integrity_regularly_checked(self.test_id)

        assert result == 'Pass'

    @patch.object(cis_audit, "shellexec", mock_filesystem_integrity_fail)
    def test_filesystem_integrity_fail(self):
        result = self.test.audit_filesystem_integrity_regularly_checked(self.test_id)

        assert result == 'Fail'

    @patch.object(cis_audit, "shellexec", mock_filesystem_integrity_error)
    def test_filesystem_integrity_pass_error(self):
        result = self.test.audit_filesystem_integrity_regularly_checked(self.test_id)

        assert result == 'Error'
