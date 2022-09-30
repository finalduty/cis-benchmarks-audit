#!/usr/bin/env python3

import os

import pytest

import cis_audit
from tests.integration import shellexec


# @pytest.fixture()
class CreateTestFile(object):
    def __init__(self, mode: str, user='root', group='root'):
        self.mode = mode
        self.user = user
        self.group = group

    def __enter__(self):
        shellexec(f'install -o {self.user} -g {self.group} -m {self.mode} /dev/null /tmp/pytest')

    # yield None

    def __exit__(self, *args):
        os.remove('/tmp/pytest')


class TestFileOwnership:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '/tmp/pytest'
    user = 'root'
    group = 'root'

    def test_integrate_audit_file_permissions_fail_user(self):
        user = 'pytest'
        mode = '0755'

        with CreateTestFile(mode='0755'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=user, expected_group=self.group, expected_mode=mode)
            assert state == 1

    def test_integrate_audit_file_permissions_fail_group(self):
        group = 'pytest'
        mode = '0755'

        with CreateTestFile(mode='0755'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=group, expected_mode=mode)
            assert state == 2


class TestFilePermissionErrors:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '/tmp/pytest'
    user = 'root'
    group = 'root'

    def test_integrate_file_permissions_error_file_not_found(self, caplog, capsys):
        mode = '0644'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == -1
        assert caplog.records[0].msg == f'Error trying to stat file {self.file}: "[Errno 2] No such file or directory: \'/tmp/pytest\'"'


class TestFilePermissions:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '/tmp/pytest'
    user = 'root'
    group = 'root'

    def test_integrate_audit_file_permissions_require_0000_mock_0000_pass(self):
        mode = '0000'
        with CreateTestFile(mode='0000'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 0

    def test_integrate_audit_file_permissions_require_0644_mock_0644_pass(self):
        mode = '0644'
        with CreateTestFile(mode='0644'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 0

    def test_integrate_audit_file_permissions_require_1400_mock_0400_fail(self):
        mode = '0400'
        with CreateTestFile(mode='1400'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 16

    def test_integrate_audit_file_permissions_require_1777_mock_1777_pass(self):
        mode = '1777'
        with CreateTestFile(mode='1777'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 0

    def test_integrate_audit_file_permissions_require_2555_mock_2555_pass(self):
        mode = '2555'
        with CreateTestFile(mode='2555'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 0

    def test_integrate_audit_file_permissions_require_0644_mock_0664_fail(self):
        mode = '0644'
        with CreateTestFile(mode='0664'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 512

    def test_integrate_audit_file_permissions_require_755_mock_664_fail(self):
        ## This test should fail because the group has write permissions
        mode = '755'
        with CreateTestFile(mode='0664'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 512

    def test_integrate_audit_file_permissions_require_0755_mock_0777_fail(self):
        mode = '0755'
        with CreateTestFile(mode='0777'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
            assert state == 512 + 4096


class TestFilePermissionFailureStates:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '/tmp/pytest'
    user = 'root'
    group = 'root'
    mode = '0000'

    def test_integrate_file_permissions_failure_state_4(self):
        with CreateTestFile(mode='4000'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 4

    def test_integrate_file_permissions_failure_state_8(self):
        with CreateTestFile(mode='2000'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 8

    def test_integrate_file_permissions_failure_state_16(self):
        with CreateTestFile(mode='1000'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 16

    def test_integrate_file_permissions_failure_state_32(self):
        with CreateTestFile(mode='0400'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 32

    def test_integrate_file_permissions_failure_state_64(self):
        with CreateTestFile(mode='0200'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 64

    def test_integrate_file_permissions_failure_state_128(self):
        with CreateTestFile(mode='0100'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 128

    def test_integrate_file_permissions_failure_state_256(self):
        with CreateTestFile(mode='0040'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 256

    def test_integrate_file_permissions_failure_state_512(self):
        with CreateTestFile(mode='0020'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 512

    def test_integrate_file_permissions_failure_state_1024(self):
        with CreateTestFile(mode='0010'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 1024

    def test_integrate_file_permissions_failure_state_2048(self):
        with CreateTestFile(mode='0004'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 2048

    def test_integrate_file_permissions_failure_state_4096(self):
        with CreateTestFile(mode='0002'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 4096

    def test_integrate_file_permissions_failure_state_8192(self):
        with CreateTestFile(mode='0001'):
            state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
            assert state == 8192


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
