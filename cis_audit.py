#!/usr/bin/env python3

# Copyright (C) 2022 Andy Dustin <andy.dustin@gmail.com>
# This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# https://creativecommons.org/licenses/by-nc-sa/4.0/

# This unofficial tool checks for your system against published CIS Hardening Benchmarks and offers an indication of your system's preparedness for compliance to the official standard.

# You can obtain a copy of the CIS Benchmarks from https://www.cisecurity.org/cis-benchmarks/
# Use of the CIS Benchmarks are subject to the Terms of Use for Non-Member CIS Products - https://www.cisecurity.org/terms-of-use-for-non-member-cis-products

__version__ = '0.20.0-alpha.2'

### Imports ###
import json  # https://docs.python.org/3/library/json.html
import logging  # https://docs.python.org/3/library/logging.html
import os  # https://docs.python.org/3/library/os.html
import pdb  # noqa https://docs.python.org/3/library/pdb.html
import re  # https://docs.python.org/3/library/re.html
import stat  # https://docs.python.org/3/library/stat.html
import subprocess  # https://docs.python.org/3/library/subprocess.html
import sys  # https://docs.python.org/3/library/sys.html
from argparse import ArgumentParser  # https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser
from argparse import RawTextHelpFormatter  # https://docs.python.org/3/library/argparse.html#argparse.RawTextHelpFormatter
from datetime import datetime  # https://docs.python.org/3/library/datetime.html#datetime.datetime
from grp import getgrgid  # https://docs.python.org/3/library/grp.html#grp.getgrgid
from pwd import getpwuid  # https://docs.python.org/3/library/pwd.html#pwd.getpwuid
from types import SimpleNamespace  # https://docs.python.org/3/library/types.html#types.SimpleNamespace
from typing import Generator  # https://docs.python.org/3/library/typing.html#typing.Generator


### Classes ###
class CISAudit:
    def __init__(self, config=None):
        if config:
            self.config = config
        else:
            self.config = SimpleNamespace(includes=None, excludes=None, level=0, system_type='server', log_level='DEBUG')

        logging.basicConfig(
            format='%(asctime)s [%(levelname)s]: %(funcName)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

        self.log = logging.getLogger(__name__)
        self.log.setLevel(self.config.log_level)

    def _get_homedirs(self) -> "Generator[str, int, str]":
        cmd = R"awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1,$3,$6 }' /etc/passwd"
        r = self._shellexec(cmd)

        for row in r.stdout:
            if row != "":
                user, uid, homedir = row.split(' ')

                yield user, int(uid), homedir

    def _get_utcnow(self) -> datetime:
        return datetime.utcnow()

    def _shellexec(self, command: str) -> "SimpleNamespace[str, str, int]":
        """Execute shell command on the system. Supports piped commands

        Parameters
        ----------
        command : string, required
            Shell command to execute

        Returns
        -------
        Namespace:

        """

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = result.stdout.decode('UTF-8').split('\n')
        error = result.stderr.decode('UTF-8').split('\n')
        returncode = result.returncode

        return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)

    def _test_is_included(self, test_id, test_level) -> bool:
        """Check whether a test_id should be tested or not

        Parameters
        ----------

        test_id : string, required
            test_id of be checked

        test_level : int, required
            Hardening level of the test_id, per the CIS Benchmarks

        config : namespace, required
            Script configuration from parse_args()

        Returns
        -------
        bool
            Returns a boolean indicating whether a test should be executed (True), or not (False)
        """

        self.log.debug(f'Checking whether to run test {test_id}')

        is_test_included = True

        ## Check if the level is one we're going to run
        if self.config.level != 0:
            if test_level != self.config.level:
                self.log.debug(f'Excluding level {test_level} test {test_id}')
                is_test_included = False

        ## Check if there were explicitly included tests:
        if self.config.includes:
            is_parent_test = False
            is_child_test = False

            ## Check if include starts with test_id
            for include in self.config.includes:
                if include.startswith(test_id):
                    is_parent_test = True
                    break

            ## Check if test_id starts with include
            for include in self.config.includes:
                if test_id.startswith(include):
                    is_child_test = True
                    break

            ## Check if the test_id is in the included tests
            if test_id in self.config.includes:
                self.log.debug(f'Test {test_id} was explicitly included')
                is_test_included = True

            elif is_parent_test:
                self.log.debug(f'Test {test_id} is the parent of an included test')
                is_test_included = True

            elif is_child_test:
                self.log.debug(f'Test {test_id} is the child of an included test')
                is_test_included = True

            elif self.config.level == 0:
                self.log.debug(f'Excluding test {test_id} (Not found in the include list)')
                is_test_included = False

        ## If this test_id was included in the tests, check it wasn't then excluded
        if self.config.excludes:
            is_parent_excluded = False

            for exclude in self.config.excludes:
                if test_id.startswith(exclude):
                    is_parent_excluded = True
                    break

            if test_id in self.config.excludes:
                self.log.debug(f'Test {test_id} was explicitly excluded')
                is_test_included = False

            elif is_parent_excluded:
                self.log.debug(f'Test {test_id} is the child of an excluded test')
                is_test_included = False

        if is_test_included:
            self.log.debug(f'Including test {test_id}')
        else:
            self.log.debug(f'Not including test {test_id}')

        return is_test_included

    def audit_access_to_su_command_is_restricted(self) -> int:
        state = 0
        cmd = R"grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su"

        r = self._shellexec(cmd)

        if r.stdout[0] == '':
            state += 1
        else:
            for entry in r.stdout[0].split():
                if entry.startswith('group='):
                    group = entry.split('=')
                    break

            cmd = f'grep {group} /etc/group'
            r = self._shellexec(cmd)
            regex = re.compile('^[a-z-]+:x:[0-9]+:$')

            if not regex.match(r.stdout[0]):
                state += 2

        return state

    def audit_at_is_restricted_to_authorized_users(self) -> int:
        state = 0

        if os.path.exists('/etc/at.deny'):
            state += 1

        if self.audit_file_permissions(file="/etc/at.allow", expected_user="root", expected_group="root", expected_mode="0600") != 0:
            state += 2

        return state

    def audit_audit_config_is_immutable(self) -> int:
        cmd = R'grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1'
        r = self._shellexec(cmd)

        if r.stdout[0] == '-e 2':
            state = 0
        else:
            state = 1

        return state

    def audit_audit_log_size_is_configured(self) -> int:
        cmd = R"grep '^max_log_file\s*=\s*[0-9]+' /etc/audit/auditd.conf"
        r = self._shellexec(cmd)

        if r.returncode == 0:
            state = 0
        else:
            state = 1

        return state

    def audit_audit_logs_not_automatically_deleted(self) -> int:
        cmd = R"grep '^max_log_file\s*=\s*keep_logs' /etc/audit/auditd.conf"
        r = self._shellexec(cmd)

        if r.returncode == 0:
            state = 0
        else:
            state = 1

        return state

    def audit_auditing_for_processes_prior_to_start_is_enabled(self) -> int:
        r"""
        #!/bin/bash
        efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
        gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
        if [ -f "$efidir"/grub.cfg ]; then
            grep "^\s*linux" "$efidir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
        elif [ -f "$gbdir"/grub.cfg ]; then
            grep "^\s*linux" "$gbdir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
        else
            echo "FAILED"
        fi
        """

        state = 0
        efidirfile = self._shellexec(R"find /boot/efi/EFI/ -type f -name 'grub.cfg' | grep -v BOOT").stdout[0]
        grubdirfile = self._shellexec(R"find /boot -mindepth 1 -maxdepth 2 -type f -name 'grub.cfg'").stdout[0]

        if efidirfile != '':
            cmd = Rf'grep "^\s*linux" "{efidirfile}" | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"'
            r = self._shellexec(cmd)
        elif grubdirfile != '':
            cmd = Rf'grep "^\s*linux" "{grubdirfile}" | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"'
            r = self._shellexec(cmd)
        else:
            r = self._shellexec("echo FAILED")

        if r.stdout[0] != 'PASSED':
            state += 1

        return state

    def audit_auth_for_single_user_mode(self) -> int:
        state = 0
        success_strings = [
            'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --job-mode=fail --no-block default"',
            'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --job-mode=fail --no-block default"',
        ]

        cmd = R"grep /sbin/nologin /usr/lib/systemd/system/rescue.service"
        r = self._shellexec(cmd)
        if r.stdout[0] not in success_strings:
            state += 1

        cmd = R"grep /sbin/nologin /usr/lib/systemd/system/rescue.service"
        r = self._shellexec(cmd)
        if r.stdout[0] not in success_strings:
            state += 2

        return state

    def audit_bootloader_password_is_set(self) -> int:
        state = 0

        cmd = R'grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg'
        r = self._shellexec(cmd)

        if not r.stdout[0].startswith('GRUB2_PASSWORD='):
            state += 1

        return state

    def audit_chrony_is_configured(self) -> int:
        state = 0

        cmd = R"systemctl is-enabled chronyd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enabled":
            state += 1

        cmd = R"systemctl is-active chronyd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "active":
            state += 2

        cmd = R'grep -E "^(server|pool)" /etc/chrony.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] == "":
            state += 4

        cmd = R"ps aux | grep chronyd | grep -Ev 'awk|grep'  | awk '/chronyd/ {print $1}'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "chrony":
            state += 8

        return state

    def audit_core_dumps_restricted(self) -> int:
        state = 0

        cmd = R'grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf /etc/security/limits.d/*'
        r = self._shellexec(cmd)
        if r.stdout[0] != "* hard core 0":
            state += 1

        cmd = R"sysctl fs.suid_dumpable"
        r = self._shellexec(cmd)
        if r.stdout[0] != "fs.suid_dumpable = 0":
            state += 2

        cmd = R'grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*'
        r = self._shellexec(cmd)
        if r.stdout[0] != "fs.suid_dumpable = 0":
            state += 4

        return state

    def audit_cron_is_restricted_to_authorized_users(self) -> int:
        state = 0

        if os.path.exists('/etc/cron.deny'):
            state += 1

        if self.audit_file_permissions(file="/etc/cron.allow", expected_user="root", expected_group="root", expected_mode="0600") != 0:
            state += 2

        return state

    def audit_default_group_for_root(self) -> int:
        cmd = 'grep "^root:" /etc/passwd | cut -f4 -d:'
        r = self._shellexec(cmd)

        if r.stdout[0] == '0':
            state = 0
        else:
            state = 1

        return state

    def audit_duplicate_gids(self) -> int:
        state = 0
        cmd = R'cut -d: -f3 /etc/group | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_group_names(self) -> int:
        state = 0
        cmd = R'cut -d: -f1 /etc/group | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_uids(self) -> int:
        state = 0
        cmd = R'cut -d: -f3 /etc/passwd | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_user_names(self) -> int:
        state = 0
        cmd = R'cut -d: -f1 /etc/passwd | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_etc_passwd_accounts_use_shadowed_passwords(self) -> int:
        """audit_etc_passwd_accounts_use_shadowed_passwords _summary_

        Returns
        -------
        int
            _description_
        """
        """
        Refer to passwd(5) for details on the fields in the file
        """
        state = 0
        ## Note: the 'awk' command from the benchmark would be the better/tidier way to do it, but I couldn't get the mixed quote marks to work from Python, so I ended up with the following:
        ## Original - awk -F: '($2 != "x" ) {print $1}' /etc/passwd
        cmd = R"grep -Ev '^[a-z-]+:x:' /etc/passwd"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 1

        return state

    def audit_etc_passwd_gids_exist_in_etc_group(self) -> int:
        gids_from_etc_group = self._shellexec("awk -F: '{print $3}' /etc/group | sort -un").stdout
        gids_from_etc_passwd = self._shellexec("awk -F: '{print $4}' /etc/passwd | sort -un").stdout
        state = 0

        for gid in gids_from_etc_passwd:
            if gid not in gids_from_etc_group:
                self.log.warning(f'GID {gid} exists in /etc/passwd but not in /etc/group')
                state = 1

        return state

    def audit_etc_shadow_password_fields_are_not_empty(self) -> int:
        state = 0

        cmd = R"grep -E '^[a-z-]+::' /etc/shadow"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 1

        return state

    def audit_events_for_changes_to_sysadmin_scope_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k scope' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k scope'"

        expected_output = [
            '-w /etc/sudoers -p wa -k scope',
            '-w /etc/sudoers.d -p wa -k scope',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_discretionary_access_control_changes_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k perm_mod' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k perm_mod'"

        expected_output = [
            '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_file_deletion_by_users_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k scope' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k scope'"

        expected_output = [
            '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
            '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_kernel_module_loading_and_unloading_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k actions' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k actions'"

        expected_output = [
            '-w /sbin/insmod -p x -k modules',
            '-w /sbin/rmmod -p x -k modules',
            '-w /sbin/modprobe -p x -k modules',
            '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_login_and_logout_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k logins' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k logins'"

        expected_output = [
            '-w /var/log/lastlog -p wa -k logins',
            '-w /var/run/faillock/ -p wa -k logins',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_session_initiation_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k [buw]tmp' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k logins'"

        expected_output = [
            '-w /var/run/utmp -p wa -k session',
            '-w /var/log/wtmp -p wa -k logins',
            '-w /var/log/btmp -p wa -k logins',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_successful_file_system_mounts_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k mounts' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k mounts'"

        expected_output = [
            '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
            '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_system_administrator_commands_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k actions' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k actions'"

        expected_output = [
            '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions',
            '-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_unsuccessful_file_access_attempts_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k mounts' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k mounts'"

        expected_output = [
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_that_modify_datetime_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k time-change' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k time-change'"

        expected_output = [
            '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
            '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change',
            '-a always,exit -F arch=b64 -S clock_settime -k time-change',
            '-a always,exit -F arch=b32 -S clock_settime -k time-change',
            '-w /etc/localtime -p wa -k time-change',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_that_modify_mandatory_access_controls_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k MAC-policy' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k MAC-policy'"

        expected_output = [
            '-w /etc/selinux/ -p wa -k MAC-policy',
            '-w /usr/share/selinux/ -p wa -k MAC-policy',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_that_modify_network_environment_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k system-locale' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k system-locale'"

        expected_output = [
            '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
            '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale',
            '-w /etc/sysconfig/network -p wa -k system-locale',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_that_modify_usergroup_info_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -- '-k identity' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep -- '-k identity'"

        expected_output = [
            '-w /etc/group -p wa -k identity',
            '-w /etc/passwd -p wa -k identity',
            '-w /etc/gshadow -p wa -k identity',
            '-w /etc/shadow -p wa -k identity',
            '-w /etc/security/opasswd -p wa -k identity',
            '',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_file_permissions(self, file: str, expected_mode: str, expected_user: str = None, expected_group: str = None) -> int:
        """Check that a file's ownership matches the expected_user and expected_group, and that the file's permissions match or are more restrictive than the expected_mode.

        Parameters
        ----------
        test_id: str, required
            The ID of the recommendation to be tested, per the CIS Benchmarks

        file: str, required
            The file to be tested

        expected_user: str, required
            The expected user for the file

        expected_group: str, required
            The expected group membership for the file

        expected_mode: str, required
            The octal file mode that the file should not exceed. e.g. 2750, 664, 0400.

        Response
        --------
        int:
            Exit state for tests as a sum of individual failures:
            -1 >= Error
             0 == Pass
             1 <= Fail

        """
        """
            When looping over each of the permission bits. If the bits do not match or are not more restrictive, increment the failure state value by a unique amount, per below. This allows us to determine from the return value, which permissions did not match:
            
              index | penalty | description
             -------|---------|-------------
                -   |   1     | User did not match
                -   |   2     | Group did not match
                0   |   4     | SetUID bit did not match
                1   |   8     | SetGID bit did not match
                2   |   16    | Sticky bit did not match
                3   |   32    | User Read bit did not match
                4   |   64    | User Write bit did not match
                5   |   128   | User Execute bit did not match
                6   |   256   | Group Read bit did not match
                7   |   512   | Group Write bit did not match
                8   |   1024  | Group Execute bit did not match
                9   |   2048  | Other Read bit did not match
                10  |   4096  | Other Write bit did not match
                11  |   8192  | Other Execute bit did not match
        """
        state = 0

        ## Convert expected_mode to binary string
        if len(expected_mode) in [3, 4]:
            if expected_mode[0] == '0':
                expected_mode = expected_mode[-3:]  # Strip leading zero otherwise it can break things, e.g. 0750 -> 750
        else:
            raise ValueError(f'The "expected_mode" for {file} should be 3 or 4 characters long, not {len(expected_mode)}')
        octal_expected_mode = oct(int(expected_mode, 8))  # Convert octal (base8) file mode to decimal (base10)
        binary_expected_mode = str(format(int(octal_expected_mode, 8), '012b'))  # Convert decimal (base10) to binary (base2) for bit-by-bit comparison

        ## Get file stats and user/group
        try:
            file_stat = os.stat(file)
        except Exception as e:
            self.log.warning(f'Error trying to stat file {file}: "{e}"')
            return -1

        file_user = getpwuid(file_stat.st_uid).pw_name
        file_group = getgrgid(file_stat.st_gid).gr_name

        ## Convert file_mode to binary string
        file_mode = int(stat.S_IMODE(file_stat.st_mode))
        octal_file_mode = oct(file_mode)
        binary_file_mode = str(format(int(file_mode), '012b'))

        if expected_user is not None:
            ## Set fail state if user does not match expectation
            if file_user != expected_user:
                state += 1
                self.log.debug(f'Test failure: file_user "{file_user}" for {file} did not match expected_user "{expected_user}"')

        if expected_group is not None:
            ## Set fail state if group does not match expecation
            if file_group != expected_group:
                state += 2
                self.log.debug(f'Test failure: file_group "{file_group}" for {file} did not match expected_group "{expected_group}"')

        ## Iterate over all bits in the binary_file_mode to ensure they're equal to, or more restrictive than, the expected_mode. Refer to the table in the description above for what the individual 'this_failure_score' values refer to.
        for i in range(len(binary_file_mode)):
            if binary_expected_mode[i] == '0':
                if binary_file_mode[i] != '0':
                    ## Add unique state so we can identify which bit a permission failed on, for debugging
                    this_failure_score = 2 ** (i + 2)
                    state += this_failure_score
                    self.log.debug(f'Test comparison for {file}, {octal_expected_mode}>={octal_file_mode} {binary_expected_mode[i]} == {binary_file_mode[i]}. Failed at index {i}. Adding {this_failure_score} to state')
                else:
                    self.log.debug(f'Test comparison for {file}, {octal_expected_mode}>={octal_file_mode} {binary_expected_mode[i]} == {binary_file_mode[i]}. Passed at index {i}')

        return state

    def audit_filesystem_integrity_regularly_checked(self) -> int:
        state = 1

        cmd = R'grep -r aide /etc/cron.* /etc/crontab /var/spool/cron/root /etc/anacrontab'
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state = 0

        else:
            cmd1 = 'systemctl is-enabled aidecheck.service'
            cmd2 = 'systemctl is-enabled aidecheck.timer'
            cmd3 = 'systemctl is-active aidecheck.timer'

            r1 = self._shellexec(cmd1)
            r2 = self._shellexec(cmd2)
            r3 = self._shellexec(cmd3)

            if all(
                [
                    r1.stdout[0] == 'enabled',
                    r2.stdout[0] == 'enabled',
                    r3.stdout[0] == 'active',
                ]
            ):
                state = 0

        return state

    def audit_firewalld_default_zone_is_set(self) -> int:
        cmd = 'firewall-cmd --get-default-zone'
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state = 0
        else:
            state = 1

        return state

    def audit_gdm_last_user_logged_in_disabled(self) -> int:
        state = 0

        if self.audit_package_is_installed(package="gdm") == 0:
            ## Test contents of /etc/dconf/profile/gdm if it exists
            file = "/etc/dconf/profile/gdm"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "user-db:user" not in contents:
                        state += 2
                    if "system-db:gdm" not in contents:
                        state += 4
                    if "file-db:/usr/share/gdm/greeter-dconf-defaults" not in contents:
                        state += 8
            else:
                state += 1

            ## Test contents of /etc/dconf/db/gdm.d/01-banner-message, if it exists
            file = "/etc/dconf/db/gdm.d/01-banner-message"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "[org/gnome/login-screen]\ndisable-user-list=true" not in contents:
                        state += 32
            else:
                state += 16

        else:
            state = -2

        return state

    def audit_gdm_login_banner_configured(self) -> int:
        state = 0

        if self.audit_package_is_installed(package="gdm") == 0:
            ## Test contents of /etc/dconf/profile/gdm if it exists
            file = "/etc/dconf/profile/gdm"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "user-db:user" not in contents:
                        state += 2
                    if "system-db:gdm" not in contents:
                        state += 4
                    if "file-db:/usr/share/gdm/greeter-dconf-defaults" not in contents:
                        state += 8
            else:
                state += 1

            ## Test contents of /etc/dconf/db/gdm.d/01-banner-message, if it exists
            file = "/etc/dconf/db/gdm.d/01-banner-message"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "[org/gnome/login-screen\nbanner-message-enable=true\nbanner-message-text=" not in contents:
                        state += 32
            else:
                state += 16
        else:
            state = -2

        return state

    def audit_gpgcheck_is_activated(self) -> int:
        state = 0

        cmd = R'grep ^\s*gpgcheck /etc/yum.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'gpgcheck=1':
            state += 1

        cmd = R"awk -v 'RS=[' -F '\n' '/\n\s*name\s*=\s*.*$/ && ! /\n\s*enabled\s*=\s*0(\W.*)?$/ && ! /\n\s*gpgcheck\s*=\s*1(\W.*)?$/ { t=substr($1, 1, index($1, \"]\")-1); print t, \"does not have gpgcheck enabled.\" }' /etc/yum.repos.d/*.repo"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 2

        return state

    def audit_homedirs_exist(self) -> int:
        state = 0
        # homedirs = self._shellexec(R"awk -F: '{print $6}' /etc/passwd").stdout

        # for dir in homedirs:
        for user, uid, homedir in self._get_homedirs():
            if homedir != '':
                if not os.path.isdir(homedir):
                    self.log.warning(f'The homedir {homedir} does not exist')
                    state = 1

        return state

    def audit_homedirs_ownership(self) -> int:
        state = 0

        for user, uid, homedir in self._get_homedirs():
            dir = os.stat(homedir)

            if dir.st_uid != int(uid):
                state = 1
                self.log.warning(f'{user}({uid}) does not own {homedir}')

        return state

    def audit_homedirs_permissions(self) -> int:
        state = 0

        for user, uid, homedir in self._get_homedirs():
            if self.audit_file_permissions(homedir, '0750') != 0:
                state = 1
                self.log.warning(f'Homedir {homedir} is not 0750 or more restrictive')

        return state

    def audit_iptables_default_deny_policy(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd1 = 'iptables -S INPUT'
            cmd2 = 'iptables -S FORWARD'
            cmd3 = 'iptables -S OUTPUT'
        elif ip_version == 'ipv6':
            cmd1 = 'ip6tables -S INPUT'
            cmd2 = 'ip6tables -S FORWARD'
            cmd3 = 'ip6tables -S OUTPUT'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout[0] != '-P INPUT DROP':
            state += 1

        if r2.stdout[0] != '-P FORWARD DROP':
            state += 2

        if r3.stdout[0] != '-P OUTPUT DROP':
            state += 4

        return state

    def audit_iptables_is_flushed(self) -> int:
        state = 0

        cmd = R"iptables -S"
        r = self._shellexec(cmd)
        if r.stdout != [
            "-P INPUT ACCEPT",
            "-P FORWARD ACCEPT",
            "-P OUTPUT ACCEPT",
        ]:
            state += 1

        cmd = R"ip6tables -S"
        r = self._shellexec(cmd)
        if r.stdout != [
            "-P INPUT ACCEPT",
            "-P FORWARD ACCEPT",
            "-P OUTPUT ACCEPT",
        ]:
            state += 2

        return state

    def audit_iptables_loopback_is_configured(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd1 = "iptables -S INPUT"
            cmd2 = "iptables -S OUTPUT"
        elif ip_version == 'ipv6':
            cmd1 = "ip6tables -S INPUT"
            cmd2 = "ip6tables -S OUTPUT"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        regex = re.compile('^-P INPUT (ACCEPT|REJECT|DROP)$')
        if regex.match(r1.stdout[0]) is None:
            state += 1

        if len(r1.stdout) < 2 or r1.stdout[1] != '-A INPUT -i lo -j ACCEPT':
            state += 2

        if len(r1.stdout) < 3 or r1.stdout[2] != '-A INPUT -s 127.0.0.0/8 -j DROP':
            state += 4

        regex = re.compile('^-P OUTPUT (ACCEPT|REJECT|DROP)$')
        if regex.match(r2.stdout[0]) is None:
            state += 8

        if len(r2.stdout) < 2 or r2.stdout[1] != '-A OUTPUT -o lo -j ACCEPT':
            state += 16

        return state

    def audit_iptables_outbound_and_established(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd = R"iptables -S"
        elif ip_version == 'ipv6':
            cmd = R"ip6tables -S"

        r = self._shellexec(cmd)

        if '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 1

        if '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 2

        if '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 4

        if '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 8

        if '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 16

        if '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 32

        return state

    def audit_iptables_rules_are_saved(self, ip_version: str) -> int:
        if ip_version == 'ipv4':
            cmd = R"diff -qs -y <(iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort) <(grep -v '^#' /etc/sysconfig/iptables | sed 's/\[[0-9]*:[0-9]*\]//' | sort)"
        elif ip_version == 'ipv6':
            cmd = R"diff -qs -y <(ip6tables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort) <(grep -v '^#' /etc/sysconfig/ip6tables | sed 's/\[[0-9]*:[0-9]*\]//' | sort)"
        r = self._shellexec(cmd)

        if r.returncode == 0 and r.stdout[0] == 'Files /dev/fd/63 and /dev/fd/62 are identical':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_compress_large_logs(self) -> int:
        cmd = R'grep -E ^\s*Compress /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'Compress=yes':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_send_logs_to_rsyslog(self) -> int:
        cmd = R'grep -E ^\s*ForwardToSyslog /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'ForwardToSyslog=yes':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_write_logfiles_to_disk(self) -> int:
        cmd = R'grep -E ^\s*Compress /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'Storage=persistent':
            state = 0
        else:
            state = 1

        return state

    def audit_kernel_module_is_disabled(self, module: str) -> int:
        state = 0
        cmd = f'modprobe -n -v {module} | grep -E "({module}|install)"'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'install /bin/true ':
            pass
        elif r.stderr[0] == f'modprobe: FATAL: Module {module} not found.\n':
            pass
        else:
            state = 1

        cmd = R'lsmod'
        r = self._shellexec(cmd)

        if module in r.stdout[0]:
            state = 1

        return state

    def audit_mta_is_localhost_only(self) -> int:
        state = 0

        cmd = R"ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "":
            state += 1

        return state

    def audit_nftables_base_chains_exist(self) -> int:
        state = 0

        cmd1 = 'nft list ruleset | grep "hook input"'
        cmd2 = 'nft list ruleset | grep "hook forward"'
        cmd3 = 'nft list ruleset | grep "hook output"'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout == ['']:
            state += 1

        if r2.stdout == ['']:
            state += 2

        if r3.stdout == ['']:
            state += 4

        return state

    def audit_nftables_connections_are_configured(self) -> int:
        state = 0

        cmd1 = 'nft list ruleset | grep "hook input"'
        cmd2 = 'nft list ruleset | grep "hook output"'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != [
            'ip protocol tcp ct state established accept',
            'ip protocol udp ct state established accept',
            'ip protocol icmp ct state established accept',
        ]:
            state += 1

        if r2.stdout != [
            'ip protocol tcp ct state established,related,new accept',
            'ip protocol udp ct state established,related,new accept',
            'ip protocol icmp ct state established,related,new accept',
        ]:
            state += 2

        return state

    def audit_nftables_default_deny_policy(self) -> int:
        state = 0

        cmd1 = 'nft list ruleset | grep "hook input"'
        cmd2 = 'nft list ruleset | grep "hook forward"'
        cmd3 = 'nft list ruleset | grep "hook output"'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout[0] != 'type filter hook input priority 0; policy drop;':
            state += 1

        if r2.stdout[0] != 'type filter hook forward priority 0; policy drop;':
            state += 2

        if r3.stdout[0] != 'type filter hook output priority 0; policy drop;':
            state += 4

        return state

    def audit_nftables_loopback_is_configured(self) -> int:
        state = 0

        cmd1 = "nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'"
        cmd2 = "nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'"
        cmd3 = "nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout[0] != 'iif "lo" accept':
            state += 1

        ## See what these re.search()'s are looking for here https://regex101.com/r/9uHJ4o/1
        regex = re.compile(R'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop')
        # if not search(r'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop', r2.stdout[0]):
        if not regex.match(r2.stdout[0]):
            state += 2

        # if not search(r'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop', r3.stdout[0]):
        if not regex.match(r3.stdout[0]):
            state += 4

        return state

    def audit_nftables_table_exists(self) -> int:
        state = 0

        cmd = R'nft list tables'
        r = self._shellexec(cmd)
        if r.stdout == ['']:
            state += 1

        return state

    def audit_no_unconfined_services(self) -> int:
        state = 0

        cmd = R"ps -eZ | grep unconfined_service_t"
        r = self._shellexec(cmd)
        if r.stdout[0] != "":
            state += 1

        return state

    def audit_ntp_is_configured(self) -> int:
        state = 0

        cmd = R"systemctl is-enabled ntpd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enabled":
            state += 1

        cmd = R"systemctl is-active ntpd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "active":
            state += 2

        cmd = R'grep -E "^(server|pool)" /etc/ntp.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] == "":
            state += 4

        cmd = R'grep "^restrict" /etc/ntp.conf'
        r = self._shellexec(cmd)
        options = ["default", "kod", "nomodify", "notrap", "nopeer", "noquery"]
        for option in options:
            for line in r.stdout:
                if option not in line:
                    state += 8
                    break
            else:
                continue
            break

        cmd = R"ps aux | grep ntp | grep -v grep"
        r = self._shellexec(cmd)
        if "-u ntp:ntp" not in r.stdout[0]:
            state += 16

        return state

    def audit_nxdx_support_enabled(self) -> int:
        state = 0
        cmd = R'dmesg | grep "protection: active"'
        r = self._shellexec(cmd)
        if "protection: active" not in r.stdout[0]:
            state += 1

        return state

    def audit_only_one_package_is_installed(self, packages: str) -> int:
        ### Similar to audit_package_is_installed but requires one of many packages is installed
        cmd = f'rpm -q {packages} | grep -v "not installed"'
        r = self._shellexec(cmd)

        ## The length of stdout should be two because a newline is output as well.
        ## e.g. print(r.stdout) will show:
        ##      ['chrony-3.4-1.el7.x86_64', '']
        ##      ['chrony-3.4-1.el7.x86_64', 'ntp-4.2.6p5-29.el7.centos.2.x86_64', '']

        if len(r.stdout) == 2 and r.stdout[1] == "":
            state = 0
        else:
            state = 1

        return state

    def audit_package_is_installed(self, package: str) -> int:
        cmd = f'rpm -q {package}'
        r = self._shellexec(cmd)

        if r.returncode != 0:
            state = 1
        else:
            state = 0

        return state

    def audit_package_not_installed(self, package: str) -> int:
        cmd = f'rpm -q {package}'
        r = self._shellexec(cmd)

        if r.returncode == 1:
            state = 0
        else:
            state = 1

        return state

    def audit_package_not_installed_or_service_is_masked(self, package: str, service: str) -> int:
        state = 0

        r1 = self.audit_package_not_installed(package)
        r2 = self.audit_service_is_masked(service)

        if r1 != 0:
            state += 1

        if r2 != 0:
            state += 2

        return state

    def audit_partition_is_separate(self, partition: str) -> int:
        state = 0
        cmd = Rf'mount | grep -E "\s{partition}\s"'
        r = self._shellexec(cmd)
        if partition not in r.stdout[0]:
            state += 1

        return state

    def audit_partition_option_is_set(self, partition: str, option: str) -> int:
        state = 1
        cmd = Rf'mount | grep -E "\s{partition}\s" | grep {option}'
        r = self._shellexec(cmd)

        if partition in r.stdout[0] and option in r.stdout[0]:
            state = 0

        return state

    def audit_password_change_minimum_delay(self, expected_min_days: int = 1) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_MIN_DAYS /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,4"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) >= expected_min_days:
            state += 1

        for line in r2.stdout:
            days = line.split(':')[1]
            if not int(days) >= expected_min_days:
                state += 2
                break

        return state

    def audit_password_expiration_max_days_is_configured(self, expected_max_days: int = 365) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_MAX_DAYS /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) <= expected_max_days:
            state += 1

        for line in r2.stdout:
            days = line.split(':')[1]
            if not int(days) <= expected_max_days:
                state += 2
                break

        return state

    def audit_password_expiration_warning_is_configured(self, expected_warn_days: int = 7) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_WARN_AGE /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,4"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) >= expected_warn_days:
            state += 1

        for line in r2.stdout:
            days = line.split(':')[1]
            if not int(days) >= expected_warn_days:
                state += 2
                break

        return state

    def audit_password_hashing_algorithm(self) -> int:
        state = 0
        cmd = R"grep -P '^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?sha512(\h+.*)?$' /etc/pam.d/system-auth /etc/pam.d/password-auth"

        r = self._shellexec(cmd)

        if len(r.stdout) < 2:
            state += 1

        return state

    def audit_password_inactive_lock_is_configured(self, expected_inactive_days: int = 30) -> int:
        state = 0

        cmd1 = R"useradd -D | grep INACTIVE"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,7"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout[0].split('=')[1]:
            configured_inactive_days = int(r1.stdout[0].split('=')[1])

        if not configured_inactive_days <= expected_inactive_days:
            state += 1

        if not configured_inactive_days > 0:
            state += 2

        for line in r2.stdout:
            days = line.split(':')[1]
            if days == '':
                state += 4
                break
            elif not int(days) <= expected_inactive_days:
                state += 8
                break

        return state

    def audit_password_reuse_is_limited(self) -> int:
        state = 0
        cmd = R"grep -P '^\s*password\s+(requisite|required)\s+(pam_pwhistory\.so|pam_unix.so)\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth"

        r = self._shellexec(cmd)

        if len(r.stdout) < 2 or r.stdout[0] == '':
            state += 1

        return state

    def audit_permissions_on_log_files(self) -> int:
        cmd = R'find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \;'
        r = self._shellexec(cmd)

        if r.stdout[0] == '':
            state = 0
        else:
            state = 1

        return state

    def audit_permissions_on_private_host_key_files(self) -> int:
        state = 0
        counter = 0
        files = []

        ## Get HostKeys from sshd_config
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        regex = re.compile(R'^hostkey\s')
        for line in r.stdout:
            if regex.match(line):
                files.append(line.split()[1])

        ## Check file permissions using audit_file_permissions()
        for counter, file in enumerate(files):
            result = self.audit_file_permissions(file=file, expected_user="root", expected_group="root", expected_mode="0600")

            if result != 0:
                state += 2**counter

        return state

    def audit_permissions_on_public_host_key_files(self) -> int:
        state = 0
        counter = 0
        files = []

        ## Get HostKeys from sshd_config
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        regex = re.compile(R'^hostkey\s')
        for line in r.stdout:
            if regex.match(line):
                files.append(line.split()[1])

        ## Check file permissions using audit_file_permissions()
        for counter, file in enumerate(files):
            result = self.audit_file_permissions(file=file + '.pub', expected_user="root", expected_group="root", expected_mode="0644")

            if result != 0:
                state += 2**counter

        return state

    def audit_removable_partition_option_is_set(self, option: str) -> int:
        state = 0
        removable_mountpoints = self._shellexec("lsblk -o RM,MOUNTPOINT | awk '/1/ {print $2}'").stdout

        for mountpoint in removable_mountpoints:
            if mountpoint != "":
                cmd = Rf'findmnt -n "{mountpoint}" | grep -Ev "\b{option}\b"'
                r = self._shellexec(cmd)

                if r.stdout[0] != "":
                    state = 1

        return state

    def audit_root_is_only_uid_0_account(self) -> int:
        state = 0
        cmd = R"awk -F: '($3 == 0) { print $1 }' /etc/passwd"
        r = self._shellexec(cmd)

        if r.stdout != ['root', '']:
            state += 1

        return state

    def audit_rsyslog_default_file_permission_is_configured(self) -> int:
        cmd = R'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == '$FileCreateMode 0640':
            state = 0
        else:
            state = 1

        return state

    def audit_rsyslog_sends_logs_to_a_remote_log_host(self) -> int:
        cmd1 = R'grep -Eh "^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#\"]+\"?\b" /etc/rsyslog.conf /etc/rsyslog.d/*.conf'  # https://regex101.com/r/Ud69Ey/4
        cmd2 = R"grep -Eh '^[^#]\s*\S+\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout[0] != '':
            state = 0
        elif r2.stdout[0] != '':
            state = 0
        else:
            state = 1

        return state

    def audit_selinux_mode_is_enforcing(self) -> int:
        state = 0

        cmd = R"sestatus | awk -F: '/^Current mode:/ {print $2}'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enforcing":
            state += 1

        cmd = R"sestatus | awk -F: '/^Mode from config file:/ {print $2}'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enforcing":
            state += 2

        return state

    def audit_selinux_mode_not_disabled(self) -> int:
        state = 0

        cmd = R"sestatus | awk -F: '/^Current mode:/ {print $2}'"
        r = self._shellexec(cmd)
        if r.stdout[0] not in ["permissive", "enforcing"]:
            state += 1

        cmd = R"sestatus | awk -F: '/^Mode from config file:/ {print $2}'"
        r = self._shellexec(cmd)
        if r.stdout[0] not in ["permissive", "enforcing"]:
            state += 2

        return state

    def audit_selinux_not_disabled_in_bootloader(self) -> int:
        state = 0
        file_paths = []
        for dirpath, dirnames, filenames in os.walk('/boot/'):
            if "grub.cfg" in filenames:
                file_paths.append(dirpath)

        if len(file_paths) == 0:
            state = -1

        else:
            for i, path in enumerate(file_paths):
                cmd = Rf'grep "^\s*linux" {path}/grub.cfg | grep -E "selinux=0|enforcing=0"'
                r = self._shellexec(cmd)

                if r.stdout != ['']:
                    state += 2 ** (i + 1)

        return state

    def audit_selinux_policy_is_configured(self) -> int:
        state = 0

        cmd = R"awk -F= '/^SELINUXTYPE=/ {print $2}' /etc/selinux/config"
        r = self._shellexec(cmd)
        if r.stdout[0] != "targeted":
            state += 1

        cmd = R"sestatus | awk -F: '/Loaded policy/ {print $2}'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "targeted":
            state += 2

        return state

    def audit_service_is_active(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-active {service}'
        r = self._shellexec(cmd, check=True)
        if r.stdout[0] != 'active':
            state += 1

        return state

    def audit_service_is_disabled(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'disabled':
            state += 1

        return state

    def audit_service_is_enabled(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'enabled':
            state += 1

        return state

    def audit_service_is_enabled_and_is_active(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'enabled':
            state += 1

        cmd = f'systemctl is-active {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'active':
            state += 2

        return state

    def audit_service_is_masked(self, service) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'masked':
            state += 1

        return state

    def audit_shadow_group_is_empty(self) -> int:
        state = 0
        cmd = R"getent group shadow | awk -F: '{print $4}'"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state = 1

        return state

    def audit_sshd_config_option(self, parameter: str, expected_value: str, comparison: str = "eq") -> int:
        state = 0
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        ## Fail check if the config test fails because we can't trust the config file is correct
        if r.returncode != 0:
            state += 1

        ## Check if the parameter in the sshd_config file matches the expected_value
        for line in r.stdout:
            if line.startswith(parameter):
                ## I didn't know of a better way of doing this
                if comparison == 'eq':
                    if not line.split()[1] == expected_value:
                        state += 2

                elif comparison == 'ne':
                    if not line.split()[1] != expected_value:
                        state += 2

                elif comparison == 'ge':
                    if not int(line.split()[1]) >= int(expected_value):
                        state += 2

                elif comparison == 'gt':
                    if not int(line.split()[1]) > int(expected_value):
                        state += 2

                elif comparison == 'le':
                    if not int(line.split()[1]) <= int(expected_value):
                        state += 2

                elif comparison == 'lt':
                    if not int(line.split()[1]) < int(expected_value):
                        state += 2

                ## No need to keep checking the other lines, so we break the loop
                break

        return state

    def audit_sticky_bit_on_world_writable_dirs(self) -> int:
        cmd = R"df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)"
        r = self._shellexec(cmd)

        if r.returncode == 0 and r.stdout[0] == '':
            state = 0
        elif r.returncode == 0 and r.stdout[0] != '':
            state = 1

        return state

    def audit_sudo_commands_use_pty(self) -> int:
        state = 0
        cmd = R"grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*"
        r = self._shellexec(cmd)

        if r.stdout[0] != 'Defaults use_pty':
            state += 1

        return state

    def audit_sudo_log_exists(self) -> int:
        state = 0
        cmd = R"grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(\")?[^#;]+(\")?' /etc/sudoers /etc/sudoers.d/*"
        r = self._shellexec(cmd)

        if r.stdout[0] != 'Defaults logfile="/var/log/sudo.log"':
            state += 1

        return state

    def audit_sysctl_flags_are_set(self, flags: "list[str]", value: int) -> int:
        state = 0

        for i, flag in enumerate(flags):
            cmd = f'sysctl {flag}'
            r = self._shellexec(cmd)
            if r.stdout[0] != f'{flag} = {value}':
                state += 2 ** (i * 2)

            cmd = f'grep -h "{flag}" /etc/sysctl.conf /etc/sysctl.d/*.conf'
            # cmd = f'find /etc/sysctl.conf /etc/sysctl.d/ -regex ".*.conf"'
            r = self._shellexec(cmd)
            if r.stdout != [f'{flag} = {value}', '']:
                state += 2 ** (i * 2 + 1)

        return state

    def audit_system_accounts_are_secured(self) -> int:
        ignored_users = ['root', 'sync', 'shutdown', 'halt']
        uid_min = int(self._shellexec(R"awk '/^\s*UID_MIN/ {print $2}' /etc/login.defs").stdout[0])
        valid_shells = ['/sbin/nologin', '/bin/false']
        state = 0

        passwd_file = self._shellexec('cat /etc/passwd').stdout

        for line in passwd_file:
            user = line.split(':')[0]
            uid = int(line.split(':')[2])
            shell = line.split(':')[6]

            if user not in ignored_users and uid < uid_min:
                if shell not in valid_shells:
                    state = 1

        return state

    def audit_system_is_disabled_when_audit_logs_are_full(self) -> int:
        state = 0

        cmd1 = R"grep 'space_left_action' /etc/audit/auditd.conf"
        cmd2 = R"grep 'action_mail_acct' /etc/audit/auditd.conf"
        cmd3 = R"grep 'action_mail_acct' /etc/audit/auditd.conf"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.returncode != 0:
            state += 1

        if r2.returncode != 0:
            state += 2

        if r3.returncode != 0:
            state += 4

        return state

    def audit_updates_installed(self) -> int:
        state = 0

        cmd = R'yum -q check-update | grep -v "^$"'
        r = self._shellexec(cmd)
        if len(r.stdout) != 0:
            state += 1

        return state

    def audit_xdcmp_not_enabled(self) -> int:
        state = 0

        cmd = R"awk '{RS=\"[\"} /xdmcp/ {print $0}' /etc/gdm/custom.conf | grep -Eis '^\s*Enable\s*=\s*true'"
        r = self._shellexec(cmd)
        if r.stdout != [""]:
            state += 1

        return state

    def output(self, format: str, data: list) -> None:
        if format in ['csv', 'psv', 'tsv']:
            if format == 'csv':
                sep = ','
            elif format == 'psv':
                sep = '|'
            elif format == 'tsv':
                sep = '\t'

            self.output_csv(data, separator=sep)

        elif format == 'json':
            self.output_json(data)

        elif format == 'text':
            self.output_text(data)

    def output_csv(self, data: list, separator: str):
        ## Shorten the variable name so that it's easier to construct the print's below
        sep = separator

        ## Print Header
        print(f'ID{sep}Description{sep}Level{sep}Result{sep}Duration')

        ## Print Data
        for record in data:
            if len(record) == 2:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{sep}{sep}')
            elif len(record) == 4:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{record[2]}{sep}{record[3]}{sep}')
            elif len(record) == 5:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{record[2]}{sep}{record[3]}{sep}{record[4]}')

    def output_json(self, data):
        output = {}

        for record in data:
            id = record[0]
            output[id] = {}
            output[id]['description'] = record[1]

            if len(record) >= 3:
                output[id]['level'] = record[2]

            if len(record) >= 4:
                output[id]['result'] = record[3]

            if len(record) >= 5:
                output[id]['duration'] = record[4]

        print(json.dumps(output))

    def output_text(self, data):
        ## Set starting/minimum width of columns to fit the column headers
        width_id = len("ID")
        width_description = len("Description")
        width_level = len("Level")
        width_result = len("Result")
        width_duration = len("Duration")

        ## Find the max width of each column
        for row in data:
            row_length = len(row)

            ## In the following section, len_level and len_duration are commented out because the
            ## headers are wider than the data in the rows, so they currently don't need expanding.
            ## If I leave them uncommented, then codecov complains about the tests not covering them.

            len_id = len(str(row[0])) if row_length >= 1 else None
            len_description = len(str(row[1])) if row_length >= 2 else None
            # len_level = len(str(row[2])) if row_length >= 3 else None
            len_result = len(str(row[3])) if row_length >= 4 else None
            # len_duration = len(str(row[4])) if row_length >= 5 else None

            if len_id and len_id > width_id:
                width_id = len_id
                # print(f'Width for ID expanded to {width_id}')

            if len_description and len_description > width_description:
                width_description = len_description

            # if len_level and len_level > width_level:
            #    width_level = len_level

            if len_result and len_result > width_result:
                width_result = len_result

            # if len_duration and len_duration > width_duration:
            #    width_duration = len_duration

        ## Print column headers
        print(f'{"ID" : <{width_id}}  {"Description" : <{width_description}}  {"Level" : ^{width_level}}  {"Result" : ^{width_result}}  {"Duration" : >{width_duration}}')
        print(f'{"--" :-<{width_id}}  {"-----------" :-<{width_description}}  {"-----" :-^{width_level}}  {"------" :-^{width_result}}  {"--------" :->{width_duration}}')

        ## Print Data
        for row in data:
            id = row[0] if len(row) >= 1 else ""
            description = row[1] if len(row) >= 2 else ""
            level = row[2] if len(row) >= 3 else ""
            result = row[3] if len(row) >= 4 else ""
            duration = row[4] if len(row) >= 5 else ""

            ## Print blank row before new major sections
            if len(id) == 1:
                print()

            print(f'{id: <{width_id}}  {description: <{width_description}}  {level: ^{width_level}}  {result: ^{width_result}}  {duration: >{width_duration}}')

    def run_tests(self, tests: "list[dict]") -> dict:
        results = []

        for test in tests:
            result = ""

            ## Test ID
            test_id = test['_id']

            ## Test Description
            test_description = test['description']

            ## Test Function
            if "function" in test:
                test_function = test['function']
            else:
                test_function = None

            ## Test kwargs
            if 'kwargs' in test:
                kwargs = test['kwargs']
            else:
                kwargs = None

            ## Test Level
            if "levels" in test:
                if self.config.system_type in test['levels']:
                    test_level = test['levels'][self.config.system_type]
            else:
                test_level = None

            ## Test Type
            if "type" in test:
                test_type = test['type']
            else:
                self.log.debug(f'Test {test_id} does not explicitly define a type, so assuming it is a test')
                test_type = 'test'

            ## If a test doesn't have a function associated with it, we assume it's unimplemented
            if test_type == 'test' and test_function is None:
                test_type = 'notimplemented'

            ## Check whether this test_id is included
            if self._test_is_included(test_id, test_level):
                if test_type == 'header':
                    results.append((test_id, test_description))

                elif test_type == 'manual':
                    results.append((test_id, test_description, test_level, 'Manual'))

                elif test_type == 'skip':
                    results.append((test_id, test_description, test_level, 'Skipped'))

                elif test_type == 'notimplemented':
                    results.append((test_id, test_description, test_level, 'Not Implemented'))

                elif test_type == 'test':
                    start_time = self._get_utcnow()

                    try:
                        if kwargs:
                            self.log.debug(f'Requesting test {test_id}, {test_function.__name__} with kwargs: {kwargs}')
                            state = test_function(self, **kwargs)
                        else:
                            self.log.debug(f'Requesting test {test_id}, {test_function.__name__}')
                            state = test_function(self)

                    except Exception as e:
                        self.log.warning(f'Test {test_id} encountered an error: "{e}"')
                        state = -1

                    end_time = self._get_utcnow()
                    duration = f'{int((end_time.microsecond - start_time.microsecond) / 1000)}ms'

                    if state == 0:
                        self.log.debug(f'Test {test_id} passed')
                        result = "Pass"
                    elif state == -1:
                        result = "Error"
                    elif state == -2:
                        result = "Skipped"
                    else:
                        self.log.debug(f'Test {test_id} failed with state {state}')
                        result = "Fail"

                    results.append((test_id, test_description, test_level, result, duration))

        return results


### Benchmarks ###
benchmarks = {
    'centos7': {
        '3.1.2': [
            {'_id': "1", 'description': "Initial Setup", 'type': "header"},
            {'_id': "1.1", 'description': "Filesystem Configuration", 'type': "header"},
            {'_id': "1.1.1", 'description': "Disable unused filesystems", 'type': "header"},
            {'_id': "1.1.1.1", 'description': "Ensure mounting of cramfs is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'cramfs'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.1.2", 'description': "Ensure mounting of squashfs is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'squashfs'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.1.3", 'description': "Ensure mounting of udf is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'udf'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.2", 'description': 'Ensure /tmp is configured', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.3", 'description': 'Ensure noexec option set on /tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'noexec', 'partition': '/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.4", 'description': 'Ensure nodev option set on /tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nodev', 'partition': '/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.5", 'description': 'Ensure nosuid option set on /tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nosuid', 'partition': '/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.6", 'description': 'Ensure /dev/shm is configured', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/dev/shm'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.7", 'description': 'Ensure noexec option set on /dev/shm partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'noexec', 'partition': '/dev/shm'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.8", 'description': 'Ensure nodev option set on /dev/shm partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nodev', 'partition': '/dev/shm'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.9", 'description': 'Ensure nosuid option set on /dev/shm partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nosuid', 'partition': '/dev/shm'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.10", 'description': 'Ensure separate partition exists for /var', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/var'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.11", 'description': 'Ensure separate partition exists for /var/tmp', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/var/tmp'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.12", 'description': 'Ensure noexec option set on /var/tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'noexec', 'partition': '/var/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.13", 'description': 'Ensure nodev option set on /var/tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nodev', 'partition': '/var/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.14", 'description': 'Ensure nosuid option set on /var/tmp partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nosuid', 'partition': '/var/tmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.15", 'description': 'Ensure separate partition exists for /var/log', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/var/log'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.16", 'description': 'Ensure separate partition exists for /var/log/audit', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/var/log/audit'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.17", 'description': 'Ensure separate partition exists for /home', 'function': CISAudit.audit_partition_is_separate, 'kwargs': {'partition': '/home'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.1.18", 'description': 'Ensure nodev option set on /home partition', 'function': CISAudit.audit_partition_option_is_set, 'kwargs': {'option': 'nodev', 'partition': '/home'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.19", 'description': "Ensure noexec option set on removable media partitions", 'function': CISAudit.audit_removable_partition_option_is_set, 'kwargs': {'option': 'noexec'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.20", 'description': "Ensure nodev option set on removable media partitions", 'function': CISAudit.audit_removable_partition_option_is_set, 'kwargs': {'option': 'nodev'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.21", 'description': "Ensure nosuid option set on removable media partitions", 'function': CISAudit.audit_removable_partition_option_is_set, 'kwargs': {'option': 'nosuid'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.1.22", 'description': 'Ensure sticky bit is set on all world-writable directories', 'function': CISAudit.audit_sticky_bit_on_world_writable_dirs, 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "1.1.23", 'description': "Disable Automounting", 'function': CISAudit.audit_service_is_disabled, 'kwargs': {'service': 'autofs'}, 'levels': {'server': 1, 'workstation': 2}},
            {'_id': "1.1.24", 'description': "Disable USB Storage", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'usb-storage'}, 'levels': {'server': 1, 'workstation': 2}},
            {'_id': "1.2", 'description': "Configure Software Updates", 'type': "header"},
            {'_id': "1.2.1", 'description': "Ensure GPG keys are configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.2.2", 'description': "Ensure package manager repositories are configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.2.3", 'description': "Ensure gpgcheck is globally activated", 'function': CISAudit.audit_gpgcheck_is_activated, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.3", 'description': "Filesystem Integrity Checking", 'type': "header"},
            {'_id': "1.3.1", 'description': "Ensure AIDE is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': 'aide'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.3.2", 'description': "Ensure filesystem integrity is regularly checked", 'function': CISAudit.audit_filesystem_integrity_regularly_checked, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.4", 'description': "Secure Boot Settings", 'type': "header"},
            {'_id': "1.4.1", 'description': "Ensure bootloader password is set", 'function': CISAudit.audit_bootloader_password_is_set, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.4.2", 'description': "Ensure permissions on bootloader config are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': '/boot/grub2/grub.cfg', 'expected_user': 'root', 'expected_group': 'root', 'expected_mode': '0600'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.4.3", 'description': "Ensure authentication required for single user mode", 'function': CISAudit.audit_auth_for_single_user_mode, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.5", 'description': "Additional Process Hardening", 'type': "header"},
            {'_id': "1.5.1", 'description': "Ensure core dumps are restricted", 'function': CISAudit.audit_core_dumps_restricted, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.5.2", 'description': 'Ensure XD/NX support is enabled', 'function': CISAudit.audit_nxdx_support_enabled, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.5.3", 'description': "Ensure address space layout randomization (ASLR) is enabled", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["kernel.randomize_va_space"], 'value': 2}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.5.4", 'description': "Ensure prelink is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'prelink'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6", 'description': "Mandatory Access Control", 'type': "header"},
            {'_id': "1.6.1", 'description': "Configure SELinux", 'type': "header"},
            {'_id': "1.6.1.1", 'description': "Ensure SELinux is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': 'libselinux'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6.1.2", 'description': "Ensure SELinux is not disabled in bootloader configuration", 'function': CISAudit.audit_selinux_not_disabled_in_bootloader, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6.1.3", 'description': "Ensure SELinux policy is configured", 'function': CISAudit.audit_selinux_policy_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6.1.4", 'description': "Ensure the SELinux mode is enforcing or permissive", 'function': CISAudit.audit_selinux_mode_not_disabled, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6.1.5", 'description': "Ensure the SELinux mode is enforcing", 'function': CISAudit.audit_selinux_mode_is_enforcing, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "1.6.1.6", 'description': "Ensure no unconfined services exist", 'function': CISAudit.audit_no_unconfined_services, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.6.1.7", 'description': "Ensure SETroubleshoot is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'setroubleshoot'}, 'levels': {'server': 1, 'workstation': None}},
            {'_id': "1.6.1.8", 'description': 'Ensure the MCS Translation Service (mcstrans) is not installed', 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'mcstrans'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7", 'description': "Command Line Warning Banners", 'type': "header"},
            {'_id': "1.7.1", 'description': "Ensure message of the day is configured properly", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7.2", 'description': "Ensure local login warning banner is configured properly", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7.3", 'description': "Ensure remote login warning banner is configured properly", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7.4", 'description': 'Ensure permissions on /etc/motd are conigured', 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': '/etc/motd', 'expected_user': 'root', 'expected_group': 'root', 'expected_mode': '0644'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7.5", 'description': 'Ensure permissions on /etc/issue are conigured', 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': '/etc/issue', 'expected_user': 'root', 'expected_group': 'root', 'expected_mode': '0644'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.7.6", 'description': 'Ensure permissions on /etc/issue.net are conigured', 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': '/etc/issue.net', 'expected_user': 'root', 'expected_group': 'root', 'expected_mode': '0644'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.8", 'description': "Gnome Display Manager", 'type': "header"},
            {'_id': "1.8.1", 'description': "Ensure GNOME Display Manager is removed", 'function': CISAudit.audit_package_not_installed, 'levels': {'server': 2, 'workstation': None}, 'kwargs': {'package': 'gdm'}},
            {'_id': "1.8.2", 'description': "Ensure GDM login banner is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.8.3", 'description': "Ensure last logged in user display is disabled", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.8.4", 'description': "Ensure XDCMP is not enabled", 'function': CISAudit.audit_xdcmp_not_enabled, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "1.9", 'description': 'Ensure updates, patches, and additional security software are installed', 'function': CISAudit.audit_updates_installed, 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "2", 'description': "Services", 'type': "header"},
            {'_id': "2.1", 'description': "inetd Services", 'type': "header"},
            {'_id': "2.1.1", 'description': "Ensure xinetd is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'xinetd'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2", 'description': "Special Purpose Services", 'type': "header"},
            {'_id': "2.2.1", 'description': "Time Synchronization", 'type': "header"},
            {'_id': "2.2.1.1", 'description': "Ensure time synchronisation is in use", 'function': CISAudit.audit_only_one_package_is_installed, 'kwargs': {'packages': "chrony ntp"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.1.2", 'description': "Ensure chrony is configured", 'function': CISAudit.audit_chrony_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.1.3", 'description': "Ensure ntp is configured", 'function': CISAudit.audit_ntp_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.2", 'description': 'Ensure X11 Server components are not installed', 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'xorg-x11-server*'}, 'levels': {'server': 1, 'workstation': None}},
            {'_id': "2.2.3", 'description': "Ensure Avahi Server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'avahi*'}, 'levels': {'server': 1, 'workstation': 2}},
            {'_id': "2.2.4", 'description': "Ensure CUPS is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'cups'}, 'levels': {'server': 1, 'workstation': None}},
            {'_id': "2.2.5", 'description': "Ensure DHCP Server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'dhcp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.6", 'description': "Ensure LDAP server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'openldap-servers'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.7", 'description': "Ensure DNS server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'bind'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.8", 'description': "Ensure FTP server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'vsftpd'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.9", 'description': "Ensure HTTP server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'httpd'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.10", 'description': 'Ensure IMAP and POP3 server is not installed', 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'dovecot'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.11", 'description': "Ensure Samba is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'samba'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.12", 'description': "Ensure HTTP Proxy server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'squid'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.13", 'description': 'Ensure net-snmp is not installed', 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'net-snmp'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.14", 'description': "Ensure NIS server is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'ypserv'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.15", 'description': 'Ensure telnet-server is not installed', 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'telnet-server'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.16", 'description': 'Ensure mail transfer agent is configured for local-only mode', 'function': CISAudit.audit_mta_is_localhost_only, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.17", 'description': 'Ensure nfs-utils is not installed or the nfs-server service is masked', 'function': CISAudit.audit_package_not_installed_or_service_is_masked, 'kwargs': {'package': "nfsutils", 'service': "nfs-server"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.18", 'description': "Ensure rpcbind is not installed or the rpcbind service is masked", 'function': CISAudit.audit_package_not_installed_or_service_is_masked, 'kwargs': {'package': "rpcbind", 'service': "rpcbind"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.2.19", 'description': "Ensure rsync is not installed or the rsyncd service is masked", 'function': CISAudit.audit_package_not_installed_or_service_is_masked, 'kwargs': {'package': "rsync", 'service': "rsyncd"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.3", 'description': "Service Clients", 'type': "header"},
            {'_id': "2.3.1", 'description': "Ensure NIS client is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'ypcbind'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.3.2", 'description': "Ensure rsh client is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'rsh'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.3.3", 'description': "Ensure talk client is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'talk'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.3.4", 'description': "Ensure telnet client is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'telnet'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.3.5", 'description': "Ensure LDAP client is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'openldap-clients'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "2.4", 'description': 'Ensure non-essential services are removed or masked', 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "3", 'description': "Network Configuration", 'type': "header"},
            {'_id': "3.1", 'description': "Disable unused network protocols and devices", 'type': "header"},
            {'_id': "3.1.1", 'description': "Disable IPv6", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv6.conf.all.disaable_ipv6", "net.ipv6.conf.default.disable_ipv6"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.1.2", 'description': "Ensure wireless interfaces are disabled", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': 'wireless-tools'}, 'levels': {'server': 1, 'workstation': 2}},
            {'_id': "3.2", 'description': 'Network Parameters (Host Only)', 'type': "header"},
            {'_id': "3.2.1", 'description': "Ensure IP forwarding is disabled", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.2.2", 'description': "Ensure packet redirect sending is disabled", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3", 'description': "Network Parameters (Host and Router", 'type': "header"},
            {'_id': "3.3.1", 'description': "Ensure source routed packets are not accepted", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route", "net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.2", 'description': "Ensure ICMP redirects are not accepted", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects", "net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.3", 'description': "Ensure secure ICMP redirects are not accepted", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.secure_redirects", "net.ipv4.conf.default.secure_redirects"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.4", 'description': "Ensure suspicious packets are logged", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.5", 'description': "Ensure broadcast ICMP requests are ignored", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.icmp_echo_ignore_broadcasts"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.6", 'description': "Ensure bogus ICMP responses are ignored", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.icmp_ignore_bogus_error_responses"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.7", 'description': "Ensure Reverse Path Filtering is enabled", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.8", 'description': "Ensure TCP SYN Cookies is enabled", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv4.tcp_syncookies"], 'value': 1}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.3.9", 'description': "Ensure IPv6 router advertisments are not accepted", 'function': CISAudit.audit_sysctl_flags_are_set, 'kwargs': {'flags': ["net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra"], 'value': 0}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.4", 'description': "Uncommon Network Protocols", 'type': "header"},
            {'_id': "3.4.1", 'description': "Ensure DCCP is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'dccp'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "3.4.1", 'description': "Ensure SCTP is disabled", 'function': CISAudit.audit_kernel_module_is_disabled, 'kwargs': {'module': 'sctp'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "3.5", 'description': "Firewall Configuration", 'type': "header"},
            {'_id': "3.5.1", 'description': "Configure firewalld", 'type': "header"},
            {'_id': "3.5.1.1", 'description': "Ensure firewalld is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': "firewalld"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.1.2", 'description': "Ensure iptables-services not installed with firewalld", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "iptables-services"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.1.3", 'description': "Ensure nftables not installed with firewalld", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "nftables"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.1.4", 'description': "Ensure firewalld service enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'kwargs': {'service': "firewalld"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.1.5", 'description': "Ensure firewalld default zone is set", 'function': CISAudit.audit_firewalld_default_zone_is_set, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.1.6", 'description': "Ensure network interfaces are assigned to appropriate zone", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "3.5.1.7", 'description': "Ensure firewalld drops unnecessary services and ports", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "3.5.2", 'description': "Configure nftables", 'type': "header"},
            {'_id': "3.5.2.1", 'description': "Ensure nftables is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': "nftables"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.2", 'description': "Ensure firewalld is not installed", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "firewalld"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.3", 'description': "Ensure iptables-services not installed with nftables", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "iptables-services"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.4", 'description': "Ensure iptables are flushed with nftables", 'function': CISAudit.audit_iptables_is_flushed, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.5", 'description': "Ensure an nftables table exists", 'function': CISAudit.audit_nftables_table_exists, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.6", 'description': "Ensure nftables base chains exist", 'function': CISAudit.audit_nftables_base_chains_exist, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.7", 'description': "Ensure nftables loopback traffic is configured", 'function': CISAudit.audit_nftables_loopback_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.8", 'description': "Ensure nftables outbound and establishe dconnections are configured", 'function': CISAudit.audit_nftables_connections_are_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.9", 'description': "Ensure nftables default deny firewall policy exists", 'function': CISAudit.audit_nftables_default_deny_policy, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.10", 'description': "Ensure nftables service is enabled", 'function': CISAudit.audit_service_is_enabled, 'kwargs': {'service': "nftables"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.2.11", 'description': "Ensure nftables rules are permanent", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3", 'description': "Configure iptables", 'type': "header"},
            {'_id': "3.5.3.1", 'description': "Configure iptables software", 'type': "header"},
            {'_id': "3.5.3.1.1", 'description': "Ensure iptables-services is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': "iptables-services"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.1.2", 'description': "Ensure nftables is not installed with iptables", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "nftables"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.1.3", 'description': "Ensure firewalld is not installed with iptables", 'function': CISAudit.audit_package_not_installed, 'kwargs': {'package': "firewalld"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.2", 'description': "Configure IPv4 iptables", 'type': "header"},
            {'_id': "3.5.3.2.1", 'description': "Ensure iptables loopback traffic is configured", 'function': CISAudit.audit_iptables_loopback_is_configured, 'kwargs': {'ip_version': 'ipv4'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.2.2", 'description': "Ensure iptables outbound and established connections are configured", 'function': CISAudit.audit_iptables_outbound_and_established, 'kwargs': {'ip_version': 'ipv4'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.2.2", 'description': "Ensure iptables rules exist for all open ports", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "3.5.3.2.4", 'description': "Ensure iptables default deny firewall policy", 'function': CISAudit.audit_iptables_default_deny_policy, 'kwargs': {'ip_version': 'ipv4'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.2.5", 'description': "Ensure iptables rules are saved", 'function': CISAudit.audit_iptables_rules_are_saved, 'kwargs': {'ip_version': 'ipv4'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.2.6", 'description': "Ensure iptables is enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'kwargs': {'service': 'iptables'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.3", 'description': "Configure IPv6 ip6tables", 'type': "header"},
            {'_id': "3.5.3.3.1", 'description': "Ensure ip6tables loopback traffic is configured", 'function': CISAudit.audit_iptables_loopback_is_configured, 'kwargs': {'ip_version': 'ipv6'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.3.2", 'description': "Ensure ip6tables outbound and established connections are configured", 'function': CISAudit.audit_iptables_outbound_and_established, 'kwargs': {'ip_version': 'ipv6'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.3.2", 'description': "Ensure ip6tables rules exist for all open ports", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "3.5.3.3.4", 'description': "Ensure ip6tables default deny firewall policy", 'function': CISAudit.audit_iptables_default_deny_policy, 'kwargs': {'ip_version': 'ipv6'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.3.5", 'description': "Ensure ip6tables rules are saved", 'function': CISAudit.audit_iptables_rules_are_saved, 'kwargs': {'ip_version': 'ipv6'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "3.5.3.3.6", 'description': "Ensure ip6tables is enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'kwargs': {'service': 'ip6tables'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4", 'description': "Logging and Auditing", 'type': "header"},
            {'_id': "4.1", 'description': "Configure System Accounting (auditd)", 'type': "header"},
            {'_id': "4.1.1", 'description': "Ensure auditing is enabled", 'type': "header"},
            {'_id': "4.1.1.1", 'description': "Ensure auditd is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': 'audit'}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.1.2", 'description': "Ensure auditd service is enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'kwargs': {'service': "auditd"}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.1.3", 'description': "Ensure auditing for processes that start prior to auditd is enabled", 'function': CISAudit.audit_auditing_for_processes_prior_to_start_is_enabled, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.2", 'description': "Configure Data Retention", 'type': "header"},
            {'_id': "4.1.2.1", 'description': "Ensure audit log storage size is configured", 'function': CISAudit.audit_audit_log_size_is_configured, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.2.2", 'description': "Ensure audit logs are not automatically deleted", 'function': CISAudit.audit_audit_logs_not_automatically_deleted, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.2.3", 'description': "Ensure system is disabled when audit logs are full", 'function': CISAudit.audit_system_is_disabled_when_audit_logs_are_full, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.2.4", 'description': "Ensure audit_backlog_limit is sufficient", 'function': None, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.3", 'description': "Ensure events that modify date and time information are collected", 'function': CISAudit.audit_events_that_modify_datetime_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.4", 'description': "Ensure events that modify user/group information are collected", 'function': CISAudit.audit_events_that_modify_usergroup_info_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.5", 'description': "Ensure events that modify the system's network environment are collected", 'function': CISAudit.audit_events_that_modify_network_environment_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.6", 'description': "Ensure events tat modify the system's Mandatory Access Controls are collected", 'function': CISAudit.audit_events_that_modify_mandatory_access_controls_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.7", 'description': "Ensure login and logout events are collected", 'function': CISAudit.audit_events_for_login_and_logout_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.8", 'description': "Ensure session initiation information is collected", 'function': CISAudit.audit_events_for_discretionary_access_control_changes_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.9", 'description': "Ensure discretionary access control permissions modification events are collected", 'function': CISAudit.audit_events_for_discretionary_access_control_changes_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.10", 'description': "Ensure unsuccessful unauthorized file access attempts are collected", 'function': CISAudit.audit_events_for_unsuccessful_file_access_attempts_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.11", 'description': "Ensure use of privileged commands is collected", 'function': None, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.12", 'description': "Ensure successful file system mounts are collected", 'function': CISAudit.audit_events_for_successful_file_system_mounts_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.13", 'description': "Ensure file deletion events by users are collected", 'function': CISAudit.audit_events_for_file_deletion_by_users_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.14", 'description': "Ensure changes to system administration scope (sudoers) is collected", 'function': CISAudit.audit_events_for_changes_to_sysadmin_scope_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.15", 'description': "Ensure system administrator command executions (sudo)are collected", 'function': CISAudit.audit_events_for_system_administrator_commands_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.16", 'description': "Ensure kernel module loading and unloading is collected", 'function': CISAudit.audit_events_for_kernel_module_loading_and_unloading_are_collected, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.1.17", 'description': "Ensure the audit configuration is immutable", 'function': CISAudit.audit_audit_config_is_immutable, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "4.2", 'description': "Configure Logging", 'type': "header"},
            {'_id': "4.2.1", 'description': "Configure rsyslog", 'type': "header"},
            {'_id': "4.2.1.1", 'description': "Ensure rsyslog is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': "rsyslog"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.1.2", 'description': "Ensure rsyslog service is enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'levels': {'server': 1, 'workstation': 1}, 'kwargs': {'service': 'rsyslog'}},
            {'_id': "4.2.1.3", 'description': "Ensure rsyslog default file permissions configured", 'function': CISAudit.audit_rsyslog_default_file_permission_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.1.4", 'description': "Ensure logging is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.1.5", 'description': "Ensure rsyslog is configured to send logs to a remote log host", 'function': CISAudit.audit_rsyslog_sends_logs_to_a_remote_log_host, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.1.6", 'description': "Ensure remote rsyslog messages are only accepted on designated log hosts", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.2", 'description': "Configure journald", 'type': "header"},
            {'_id': "4.2.2.1", 'description': "Ensure journald is configured to send logs to rsyslog", 'function': CISAudit.audit_journald_configured_to_send_logs_to_rsyslog, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.2.2", 'description': "Ensure journald is configured to compress large log files", 'function': CISAudit.audit_journald_configured_to_compress_large_logs, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.2.3", 'description': "Ensure journald is configured to write logfiles to persistent disk", 'function': CISAudit.audit_journald_configured_to_write_logfiles_to_disk, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.3", 'description': "Ensure permissions on all logfiles are configured", 'function': CISAudit.audit_permissions_on_log_files, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "4.2.4", 'description': "Ensure logrotate is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5", 'description': "Access, Authentication and Authorization", 'type': "header"},
            {'_id': "5.1", 'description': "Configure time-based job schedulers", 'type': "header"},
            {'_id': "5.1.1", 'description': "Ensure cron daemon is enabled and running", 'function': CISAudit.audit_service_is_enabled_and_is_active, 'kwargs': {'service': 'crond'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.2", 'description': "Ensure permissions on /etc/crontab are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/crontab", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0600"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.3", 'description': "Ensure permissions on /etc/cron.hourly are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/cron.hourly", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0700"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.4", 'description': "Ensure permissions on /etc/cron.daily are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/cron.daily", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0700"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.5", 'description': "Ensure permissions on /etc/cron.weekly are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/cron.weekly", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0700"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.6", 'description': "Ensure permissions on /etc/cron.monthly are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/cron.monthly", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0700"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.7", 'description': "Ensure permissions on /etc/cron.d are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/cron.d", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0700"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.8", 'description': "Ensure cron is restricted to authorized users", 'function': CISAudit.audit_cron_is_restricted_to_authorized_users, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.1.9", 'description': "Ensure at is restricted to authorized users", 'function': CISAudit.audit_at_is_restricted_to_authorized_users, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.2", 'description': "Configure sudo", 'type': "header"},
            {'_id': "5.2.1", 'description': "Ensure sudo is installed", 'function': CISAudit.audit_package_is_installed, 'kwargs': {'package': 'sudo'}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.2.2", 'description': "Ensure sudo commands use pty", 'function': CISAudit.audit_sudo_commands_use_pty, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.2.3", 'description': "Ensure sudo log file exists", 'function': CISAudit.audit_sudo_log_exists, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3", 'description': "Configure SSH Server", 'type': "header"},
            {'_id': "5.3.1", 'description': "Ensure permissions on /etc.ssh/sshd_config are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/ssh/sshd_config", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0600"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.2", 'description': "Ensure permissions on SSH private host key files are configured", 'function': CISAudit.audit_permissions_on_private_host_key_files, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.3", 'description': "Ensure permissions on SSH public host key files are configures", 'function': CISAudit.audit_permissions_on_public_host_key_files, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.4", 'description': "Ensure SSH access is limited", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.5", 'description': "Ensure SSH LogLevel is appropriate", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.6", 'description': "Ensure SSH X11 forwarding is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "x11forwarding", 'expected_value': "no"}, 'levels': {'server': 2, 'workstation': 1}},
            {'_id': "5.3.7", 'description': "Ensure SSH MaxAuthTries is set to 4 or less", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "maxauthtries", 'expected_value': "4", 'comparison': "le"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.8", 'description': "Ensure SSH IgnoreRhosts is enabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "ignorerhosts", 'expected_value': "yes"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.9", 'description': "Ensure SSH HostbasedAuthentication is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "hostbasedauthentication", 'expected_value': "no"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.10", 'description': "Ensure SSH root login is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "permitrootlogin", 'expected_value': "no"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.11", 'description': "Ensure SSH PermitEmptyPasswords is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "permitemptypasswords", 'expected_value': "no"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.12", 'description': "Ensure SSH PermitUserEnvironment is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "permituserenvironment", 'expected_value': "no"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.13", 'description': "Ensure only strong Ciphers are used", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.14", 'description': "Ensure only strong MAC algorithms are used", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.15", 'description': "Ensure only strong Key Exchange algorithms are used", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.12", 'description': "Ensure SSH Idle Timeout Interval is configured", 'type': "header"},
            {'_id': "5.3.12.1", 'description': "Ensure SSH ClientAliveInterval is 900 or less", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "clientaliveinterval", 'expected_value': "900", 'comparison': "le"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.12.2", 'description': "Ensure SSH ClientAliveCountMax is 0", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "clientalivecountmax", 'expected_value': "0"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.17", 'description': "Ensure SSH LoginGraceTime is set to one minute or less", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "logingracetime", 'expected_value': "60", 'comparison': "le"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.18", 'description': "Ensure SSH warning banner is configured", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "banner", 'expected_value': "/etc/issue.net"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.19", 'description': "Ensure SSH PAM is enabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "usepam", 'expected_value': "yes"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.20", 'description': "Ensure SSH AllowTcpForwarding is disabled", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "allowtcpforwarding", 'expected_value': "no"}, 'levels': {'server': 2, 'workstation': 2}},
            {'_id': "5.3.21", 'description': "Ensure SSH MaxStartups is configured", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "maxstartups", 'expected_value': "10:30:60"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.3.22", 'description': "Ensure SSH MaxSessions is limited", 'function': CISAudit.audit_sshd_config_option, 'kwargs': {'parameter': "maxsessions", 'expected_value': "10", 'comparison': "le"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.4", 'description': "Configure PAM", 'type': "header"},
            {'_id': "5.4.1", 'description': "Ensure password creation requirements are configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.4.2", 'description': "Ensure lockout for failed password attempts is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.4.3", 'description': "Ensure password hashing algorithm is SHA512", 'function': CISAudit.audit_password_hashing_algorithm, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.4.4", 'description': "Ensure password reuse is limited", 'function': CISAudit.audit_password_reuse_is_limited, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5", 'description': "User Accounts and Environment", 'type': "header"},
            {'_id': "5.5.1", 'description': "Set Shadow Password Suite Parameters", 'type': "header"},
            {'_id': "5.5.1.1", 'description': "Ensure password expiration is 365 days or less", 'function': CISAudit.audit_password_expiration_max_days_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.1.2", 'description': "Ensure minimum days between password changes is configured", 'function': CISAudit.audit_password_change_minimum_delay, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.1.3", 'description': "Ensure password expiration warning days is 7 or more", 'function': CISAudit.audit_password_expiration_warning_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.1.4", 'description': "Ensure inactive password lock is 30 days or less", 'function': CISAudit.audit_password_inactive_lock_is_configured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.1.5", 'description': "Ensure all users last password change date is in the past", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.2", 'description': "Ensure system accounts are secured", 'function': CISAudit.audit_system_accounts_are_secured, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.3", 'description': "Ensure default group for the root account is GID 0", 'function': CISAudit.audit_default_group_for_root, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.4", 'description': "Ensure default shell timeout is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.5.5", 'description': "Ensure default user umask is configured", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "5.6", 'description': "Ensure root login is restricted to system console", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "5.7", 'description': "Ensure access to the su command is restricted", 'function': CISAudit.audit_access_to_su_command_is_restricted, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6", 'description': "System Maintenance", 'type': "header"},
            {'_id': "6.1", 'description': "System File Permissions", 'type': "header"},
            {'_id': "6.1.1", 'description': "Audit system file permissions", 'levels': {'server': 2, 'workstation': 2}, 'type': "manual"},
            {'_id': "6.1.2", 'description': "Ensure permissions on /etc/passwd are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/passwd", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0644"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.3", 'description': "Ensure permissions on /etc/passwd- are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/passwd-", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0644"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.4", 'description': "Ensure permissions on /etc/shadow are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/shadow", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0000"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.5", 'description': "Ensure permissions on /etc/shadow- are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/shadow-", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0000"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.6", 'description': "Ensure permissions on /etc/gshadow- are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/gshadow-", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0000"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.7", 'description': "Ensure permissions on /etc/gshadow are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/gshadow", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0000"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.8", 'description': "Ensure permissions on /etc/group are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/group", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0644"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.9", 'description': "Ensure permissions on /etc/group- are configured", 'function': CISAudit.audit_file_permissions, 'kwargs': {'file': "/etc/group-", 'expected_user': "root", 'expected_group': "root", 'expected_mode': "0644"}, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.10", 'description': "Ensure no world writable files exist", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.11", 'description': "Ensure no unowned files or directories exist", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.12", 'description': "Ensure no ungrouped files or directories exist", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.1.13", 'description': "Audit SUID executables", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "6.1.14", 'description': "Audit SGID executables", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "6.2", 'description': "User and Group Settings", 'type': "header"},
            {'_id': "6.2.1", 'description': "Ensure accounts in /etc/passwd use shadowed passwords", 'function': CISAudit.audit_etc_passwd_accounts_use_shadowed_passwords, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.2", 'description': "Ensure /etc/shadow password fields are not empty", 'function': CISAudit.audit_etc_shadow_password_fields_are_not_empty, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.3", 'description': "Ensure all groups in /etc/passwd exist in /etc/group", 'function': CISAudit.audit_etc_passwd_gids_exist_in_etc_group, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.4", 'description': "Ensure shadow group is empty", 'function': CISAudit.audit_shadow_group_is_empty, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.5", 'description': "Ensure no duplicate user names exist", 'function': CISAudit.audit_duplicate_user_names, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.6", 'description': "Ensure no duplicate user names exist", 'function': CISAudit.audit_duplicate_user_names, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.7", 'description': "Ensure no duplicate UIDs exist", 'function': CISAudit.audit_duplicate_uids, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.8", 'description': "Ensure no duplicate GIDs exist", 'function': CISAudit.audit_duplicate_gids, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.9", 'description': "Ensure root is the only UID 0 account", 'function': CISAudit.audit_root_is_only_uid_0_account, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.10", 'description': "Ensure root PATH integrity", 'levels': {'server': 1, 'workstation': 1}, 'type': "manual"},
            {'_id': "6.2.11", 'description': "Ensure all users' home directories exist", 'function': CISAudit.audit_homedirs_exist, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.12", 'description': "Ensure users own their home directories", 'function': CISAudit.audit_homedirs_ownership, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.13", 'description': "Ensure users' home directory permissions are 750 or more restrictive", 'function': CISAudit.audit_homedirs_permissions, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.14", 'description': "Ensure users' dot files are not group or world writable", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.15", 'description': "Ensure no users have .forward files", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.16", 'description': "Ensure no users have .netrc files", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
            {'_id': "6.2.17", 'description': "Ensure no users have .rhosts files", 'function': None, 'levels': {'server': 1, 'workstation': 1}},
        ],
    }
}


## Script Functions ##
def main():  # pragma: no cover
    config = parse_arguments()
    audit = CISAudit(config=config)

    host_os = 'centos7'
    benchmark_version = '3.1.2'

    # test_list = audit.get_tests_list(host_os, benchmarks_version)
    test_list = benchmarks[host_os][benchmark_version]
    results = audit.run_tests(test_list)
    audit.output(config.outformat, results)


def parse_arguments(argv=sys.argv):
    description = "This script runs tests on the system to check for compliance against the CIS Benchmarks. No changes are made to system files by this script."
    epilog = f"""
Examples:
    
    Run with debug enabled:
    {__file__} --debug
        
    Exclude tests from section 1.1 and 1.3.2:
    {__file__} --exclude 1.1 1.3.2
        
    Include tests only from section 4.1 but exclude tests from section 4.1.1:
    {__file__} --include 4.1 --exclude 4.1.1
        
    Run only level 1 tests
    {__file__} --level 1
        
    Run level 1 tests and include some but not all SELinux questions
    {__file__} --level 1 --include 1.6 --exclude 1.6.1.2
    """

    level_choices = [1, 2]
    log_level_choices = ['DEBUG', 'INFO', 'WARNING', 'CRITICAL']
    output_choices = ['csv', 'json', 'psv', 'text', 'tsv']
    system_type_choices = ['server', 'workstation']
    version_str = f'{os.path.basename(__file__)} {__version__})'

    parser = ArgumentParser(description=description, epilog=epilog, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--level', action='store', choices=level_choices, default=0, type=int, help='Run tests for the specified level only')
    parser.add_argument('--include', action='store', nargs='+', dest='includes', help='Space delimited list of tests to include')
    parser.add_argument('--exclude', action='store', nargs='+', dest='excludes', help='Space delimited list of tests to exclude')
    parser.add_argument('-l', '--log-level', action='store', choices=log_level_choices, default='INFO', help='Set log output level')
    parser.add_argument('--debug', action='store_const', const='DEBUG', dest='log_level', help='Run script with debug output turned on. Equivalent to --log-level DEBUG')
    parser.add_argument('--nice', action='store_true', default=True, help='Lower the CPU priority for test execution. This is the default behaviour.')
    parser.add_argument('--no-nice', action='store_false', dest='nice', help='Do not lower CPU priority for test execution. This may make the tests complete faster but at the cost of putting a higher load on the server. Setting this overrides the --nice option.')
    parser.add_argument('--no-colour', '--no-color', action='store_true', help='Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.')
    parser.add_argument('--system-type', action='store', choices=system_type_choices, default='server', help='Set which test level to reference')
    parser.add_argument('--server', action='store_const', const='server', dest='system_type', help='Use "server" levels to determine which tests to run. Equivalent to --system-type server [Default]')
    parser.add_argument('--workstation', action='store_const', const='workstation', dest='system_type', help='Use "workstation" levels to determine which tests to run. Equivalent to --system-type workstation')
    parser.add_argument('--outformat', action='store', choices=output_choices, default='text', help='Output type for results')
    parser.add_argument('--text', action='store_const', const='text', dest='outformat', help='Output results as text. Equivalent to --output text [default]')
    parser.add_argument('--json', action='store_const', const='json', dest='outformat', help='Output results as json. Equivalent to --output json')
    parser.add_argument('--csv', action='store_const', const='csv', dest='outformat', help='Output results as comma-separated values. Equivalent to --output csv')
    parser.add_argument('--psv', action='store_const', const='psv', dest='outformat', help='Output results as pipe-separated values. Equivalent to --output psv')
    parser.add_argument('--tsv', action='store_const', const='tsv', dest='outformat', help='Output results as tab-separated values. Equivalent to --output tsv')
    parser.add_argument('-V', '--version', action='version', version=version_str, help='Print version and exit')
    parser.add_argument('-c', '--config', action='store', help='Location of config file to load')

    args = parser.parse_args(argv[1:])

    logger = logging.getLogger(__name__)

    ## --log-level
    if args.log_level == 'DEBUG':
        logger.setLevel(level=args.log_level)
        logger.debug('Debugging enabled')

    ## --nice
    if args.nice:
        logger.debug('Tests will run with reduced CPU priority')

    ## --no-colour
    if args.no_colour:
        logger.debug('Coloured output will be disabled')

    ## --include
    if args.includes:
        logger.debug(f'Include list is populated "{args.includes}"')
    else:
        logger.debug('Include list is empty')

    ## --exclude
    if args.excludes:
        logger.debug(f'Exclude list is populated "{args.excludes}"')
    else:
        logger.debug('Exclude list is empty')

    ## --level
    if args.level == 0:
        logger.debug('Going to run tests from any level')
    elif args.level == 1:
        logger.debug('Going to run Level 1 tests')
    elif args.level == 2:
        logger.debug('Going to run Level 2 tests')

    ## --system-type
    if args.system_type == 'server':
        logger.debug('Going to use "server" levels for test determination')
    elif args.system_type == 'workstation':
        logger.debug('Going to use "workstation" levels for test determination')

    ## --outformat
    if args.outformat == 'text':
        logger.debug('Going to use "text" outputter')
    elif args.outformat == 'json':
        logger.debug('Going to use "json" outputter')
    elif args.outformat == 'csv':
        logger.debug('Going to use "csv" outputter')

    return args


### Entrypoint ###
if __name__ == '__main__':  # pragma: no cover
    main()
