#!/usr/bin/env python3

from types import SimpleNamespace
import cis_audit
import pytest
from unittest.mock import patch


class MockFilePermissions:
    def __init__(self, mode):
        self.mode = mode

    def stat(self, file, **kwargs):
        uid = 0
        gid = 0
        if len(self.mode) == 4 and self.mode[0] == '0':
            mode = int(self.mode[-3:], 8)
        else:
            mode = int(self.mode, 8)

        ## Example: os.stat_result(st_mode=16877, st_ino=283998177, st_dev=16777220, st_nlink=114, st_uid=0, st_gid=0, st_size=3648, st_atime=1644784040, st_mtime=1644750635, st_ctime=1644750635)
        return SimpleNamespace(st_mode=mode, st_ino=28399, st_dev=1, st_nlink=1, st_uid=uid, st_gid=gid, st_size=4096, st_atime=1644784040, st_mtime=1644784040, st_ctime=1644784040)


class MockFileNotFoundError:
    def stat(file, **kwargs):
        print(file, file)
        raise FileNotFoundError(2, 'No such file or directory', '/pytest')


def mock_uid_gid(id):
    if id == 0:
        name = 'root'

    return SimpleNamespace(pw_name=name, gr_name=name)


@patch.object(cis_audit, "getgrgid", mock_uid_gid)
@patch.object(cis_audit, "getpwuid", mock_uid_gid)
class TestFileOwnership:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '.'
    user = 'root'
    group = 'root'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0755'))
    def test_audit_file_permissions_fail_user(self):
        user = 'pytest'
        mode = '0755'

        state = self.test.audit_file_permissions(file=self.file, expected_user=user, expected_group=self.group, expected_mode=mode)
        assert state == 1

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0755'))
    def test_audit_file_permissions_fail_group(self):
        group = 'pytest'
        mode = '0755'

        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=group, expected_mode=mode)
        assert state == 2


class TestFilePermissionErrors:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '/pytest'
    user = 'root'
    group = 'root'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0000'))
    def test_file_permission_error_mode_too_long(self, caplog):
        mode = '00100'
        with pytest.raises(ValueError) as e:
            assert self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert str(e.value) == f'The "expected_mode" for {self.file} should be 3 or 4 characters long, not {len(mode)}'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0000'))
    def test_file_permission_error_mode_too_short(self, caplog):
        mode = '10'
        with pytest.raises(ValueError) as e:
            assert self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert str(e.value) == f'The "expected_mode" for {self.file} should be 3 or 4 characters long, not {len(mode)}'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0000'))
    def test_file_permission_error_rwx_is_not_octal(self, caplog):
        mode = 'rwxr-xr-x'
        with pytest.raises(ValueError) as e:
            assert self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert str(e.value) == f'The "expected_mode" for {self.file} should be 3 or 4 characters long, not {len(mode)}'

    @patch.object(cis_audit, "os", MockFileNotFoundError)
    def test_file_permissions_error_file_not_found(self, caplog, capsys):
        mode = '0644'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == -1
        assert caplog.records[0].msg == f'Error trying to stat file {self.file}: "[Errno 2] No such file or directory: \'/pytest\'"'


@patch.object(cis_audit, "getgrgid", mock_uid_gid)
@patch.object(cis_audit, "getpwuid", mock_uid_gid)
class TestFilePermissions:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '.'
    user = 'root'
    group = 'root'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0000'))
    def test_audit_file_permissions_require_0000_mock_0000_pass(self):
        mode = '0000'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 0

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0644'))
    def test_audit_file_permissions_require_0644_mock_0644_pass(self):
        mode = '0644'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 0

    @patch.object(cis_audit, "os", MockFilePermissions(mode='1400'))
    def test_audit_file_permissions_require_1400_mock_0400_fail(self):
        mode = '0400'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 16

    @patch.object(cis_audit, "os", MockFilePermissions(mode='1777'))
    def test_audit_file_permissions_require_1777_mock_1777_pass(self):
        mode = '1777'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 0

    @patch.object(cis_audit, "os", MockFilePermissions(mode='2555'))
    def test_audit_file_permissions_require_2555_mock_2555_pass(self):
        mode = '2555'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 0

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0664'))
    def test_audit_file_permissions_require_0644_mock_0664_fail(self):
        mode = '0644'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 512

    @patch.object(cis_audit, "os", MockFilePermissions(mode='664'))
    def test_audit_file_permissions_require_755_mock_664_fail(self):
        ## This test should fail because the group has write permissions
        mode = '755'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 512

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0777'))
    def test_audit_file_permissions_require_0755_mock_0777_fail(self):
        mode = '0755'
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=mode)
        assert state == 512 + 4096


@patch.object(cis_audit, "getgrgid", mock_uid_gid)
@patch.object(cis_audit, "getpwuid", mock_uid_gid)
class TestFilePermissionFailureStates:
    test = cis_audit.CISAudit()
    test_id = '1.1'
    file = '.'
    user = 'root'
    group = 'root'
    mode = '0000'

    @patch.object(cis_audit, "os", MockFilePermissions(mode='4000'))
    def test_file_permissions_failure_state_4(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 4

    @patch.object(cis_audit, "os", MockFilePermissions(mode='2000'))
    def test_file_permissions_failure_state_8(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 8

    @patch.object(cis_audit, "os", MockFilePermissions(mode='1000'))
    def test_file_permissions_failure_state_16(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 16

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0400'))
    def test_file_permissions_failure_state_32(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 32

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0200'))
    def test_file_permissions_failure_state_64(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 64

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0100'))
    def test_file_permissions_failure_state_128(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 128

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0040'))
    def test_file_permissions_failure_state_256(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 256

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0020'))
    def test_file_permissions_failure_state_512(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 512

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0010'))
    def test_file_permissions_failure_state_1024(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 1024

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0004'))
    def test_file_permissions_failure_state_2048(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 2048

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0002'))
    def test_file_permissions_failure_state_4096(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 4096

    @patch.object(cis_audit, "os", MockFilePermissions(mode='0001'))
    def test_file_permissions_failure_state_8192(self):
        state = self.test.audit_file_permissions(file=self.file, expected_user=self.user, expected_group=self.group, expected_mode=self.mode)
        assert state == 8192


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
