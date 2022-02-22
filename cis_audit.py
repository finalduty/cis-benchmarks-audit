#!/usr/bin/env python3

## Copyright 2022 Andy Dustin <andy.dustin@gmail.com>
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
## in compliance with the License. You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software distributed under the License is
## distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and limitations under the License.


## This script checks for compliance against CIS CentOS Linux 7 Benchmark v2.1.1 2017-01-31 measures
## Each individual standard has it's own function and is forked to the background, allowing for
## multiple tests to be run in parallel, reducing execution time.
##
## You can obtain a copy of the CIS Benchmarks from https://www.cisecurity.org/cis-benchmarks/

__version__ = "0.11.0-alpha"
__revision__ = "8342248d"


### Imports ###
## Standard Libraries
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from datetime import datetime
from os import path
from sys import argv
from types import SimpleNamespace
from typing_extensions import Literal
import logging
import subprocess

## Third-party Libraries
None


### Variables ###
## This section defines global variables used in the script
#logger = logging.getLogger(__name__)
#log_format = '%(asctime)s %(levelname)s:%(message)s'
#log_time_format = '%m/%d/%Y %I:%M:%S %p'

#logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S' )
#logger = logging.getLogger(__name__)


### Classes ###
class CISAudit:
    def __init__(self, config=None):
        if config:
            self.config = config
        else:
            self.config = Namespace(includes=None, excludes=None, level=0, log_level='DEBUG')

        logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(self.config.log_level)
        
    def test_is_included(self, test_id, test_level) -> bool:
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

        self.logger.debug(f'Checking whether to run test {test_id}')

        is_test_included = True

        ## Check if the level is one we're going to run
        if self.config.level != 0:
            if test_level != self.config.level:
                self.logger.debug(f'Excluding level {test_level} test {test_id}')
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
                self.logger.debug(f'Test {test_id} was explicitly included')
                is_test_included = True

            elif is_parent_test:
                self.logger.debug(f'Test {test_id} is the parent of an included test')
                is_test_included = True

            elif is_child_test:
                self.logger.debug(f'Test {test_id} is the child of an included test')
                is_test_included = True

            elif self.config.level == 0:
                self.logger.debug(f'Excluding test {test_id} (Not found in the include list)')
                is_test_included = False

        ## If this test_id was included in the tests, check it wasn't then excluded
        if self.config.excludes:
            is_parent_excluded = False
            
            for exclude in self.config.excludes:
                if test_id.startswith(exclude):
                    is_parent_excluded = True
                    break

            if test_id in self.config.excludes:
                self.logger.debug(f'Test {test_id} was explicitly excluded')
                is_test_included = False
            
            elif is_parent_excluded:
                self.logger.debug(f'Test {test_id} is the child of an excluded test')
                is_test_included = False

        if is_test_included:
            self.logger.debug(f'Including test {test_id}')
        else:
            self.logger.debug(f'Not including test {test_id}')

        return is_test_included

    def run_test(self, test_id, test_level, test_function, **kwargs) -> str:
        if self.test_is_included(test_id, test_level):
            self.logger.debug(f'Requesting test {test_id}, {test_function.__name__} {kwargs}')

            ## Don't start threads if debug is enabled so output is tidier
            if self.config.log_level == 'DEBUG':
                ## Not implemented
                pass
            
            result = test_function(test_id, **kwargs)
            return result

    def header(self, test_id, **kwargs) -> Literal['Header']:
        return 'Header'

    def manually(self, test_id, **kwargs) -> Literal['Manual']:
        return 'Manual'

    def skip(self, test_id, **kwargs) -> Literal['Skip']:
        ## This function is a blank for any tests too complex to perform
        ## or that rely too heavily on site policy for definition
        return 'Skip'

    def audit_service_is_active(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        service = kwargs['service']

        try:
            cmd = f'systemctl is-active {service}'
            r = shellexec(cmd)

            if r.returncode == 0 and r.stdout[0] == 'active':
                result = 'Pass'
            else:
                result = 'Fail'
                
        except Exception as e:
            result = 'Error'
            self.logger.warning(f'Test {test_id} encountered an error: {e}')

        return result

    def audit_service_is_disabled(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        service = kwargs['service']

        cmd = f'systemctl is-enabled {service}'
        r = shellexec(cmd)

        if 'enabled' in r.stdout:
            return 'Fail'
        else:
            return 'Pass'

    def audit_service_is_enabled(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        service = kwargs['service']

        cmd = f'systemctl is-enabled {service}'
        r = shellexec(cmd)

        if r.returncode == 0:
            if 'enabled' in r.stdout:
                return 'Pass'
            elif 'disabled' in r.stdout:
                return 'Fail'
        else:
            return 'Error'

    def audit_package_is_installed(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        package = kwargs['package']

        cmd = f'rpm -q {package}'
        r = shellexec(cmd)

        print(r)
        if r.returncode == 0 and package in r.stdout[0]:
            return 'Pass'
        elif r.returncode == 1 and package in r.stdout[0]:
            return 'Fail'
        else:
            return 'Error'

    def audit_package_is_not_installed(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        package = kwargs['package']

        cmd = f'rpm -q {package}'
        r = shellexec(cmd)

        if r.returncode == 1 and package in r.stdout[0]:
            return 'Pass'
        elif r.returncode == 0 and package in r.stdout[0]:
            return 'Fail'
        else:
            return 'Error'

    def audit_filesystem_is_disabled(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        filesystems = kwargs['filesystems']
        state = 0

        for filesystem in filesystems:
            cmd = f'modprobe -n -v {filesystem} | grep -E "({filesystem}|install)"'
            r = shellexec(cmd)
            
            if r.stdout[0] == 'install /bin/true\n':
                pass
            elif r.stderr[0] == f'modprobe: FATAL: Module {filesystem} not found.\n':
                pass
            else:
                state = 1

            cmd = 'lsmod'
            r = shellexec(cmd)

            if filesystem in r.stdout[0]:
                state = 1

        self.logger.debug(f'Test {test_id} finished with state {state}')

        if state == 0:
            return "Pass"
        else:
            return "Fail"

    def audit_partition_is_separate(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        partition = kwargs['partition']

        cmd = rf'mount | grep -E "\s{partition}\s"'
        r = shellexec(cmd)
        print(r)
        if partition in r.stdout[0]:
            return 'Pass'
        else:
            return 'Fail'

    def audit_partition_option_is_set(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        option = kwargs['option']
        partition = kwargs['partition']

        cmd = rf'mount | grep -E "\s{partition}\s" | grep {option}'
        r = shellexec(cmd)

        if partition in r.stdout[0] and option in r.stdout[0]:
            return 'Pass'
        else:
            return 'Fail'

    def audit_sticky_bit_on_world_writable_dirs(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        cmd = r"df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)"
        r = shellexec(cmd)

        if r.returncode == 0 and r.stdout[0] == '':
            return 'Pass'
        elif r.returncode == 0 and r.stdout[0] != '':
            return 'Fail'
        else:
            return 'Error'

    def audit_gpgcheck_is_activated(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        state = 0

        try:
            cmd = r'grep ^\s*gpgcheck /etc/yum.conf'
            r = shellexec(cmd)

            if r.stdout[0] == 'gpgcheck=1':
                pass
            else:
                state += 1

            cmd = r"awk -v 'RS=[' -F '\n' '/\n\s*name\s*=\s*.*$/ && ! /\n\s*enabled\s*=\s*0(\W.*)?$/ && ! /\n\s*gpgcheck\s*=\s*1(\W.*)?$/ { t=substr($1, 1, index($1, \"]\")-1); print t, \"does not have gpgcheck enabled.\" }' /etc/yum.repos.d/*.repo"
            r = shellexec(cmd)

            if r.stdout[0] == '':
                pass
            else:
                state += 2

            if state == 0:
                result = 'Pass'
            else:
                result = 'Fail'

        except Exception as e:
            result = 'Error'
            self.logger.warning(e)

        self.logger.debug(f'Test {test_id} {result.lower()}ed with state {state}')
        return result

    def audit_sudo_commands_use_pty(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        try:
            cmd = r"grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*"
            r = shellexec(cmd)

            if r.stdout[0] == 'Defaults use_pty':
                result = 'Pass'
            else:
                result = 'Fail'
            
        except Exception as e:
            result = 'Error'
            self.logger.warning(f'Test {test_id} encountered an error: {e}')

        return result

    def audit_sudo_log_exists(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        try:
            cmd = r"grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(\")?[^#;]+(\")?' /etc/sudoers /etc/sudoers.d/*"
            r = shellexec(cmd)

            if r.stdout[0] == 'Defaults logfile="/var/log/sudo.log"':
                result = 'Pass'
            else:
                result = 'Fail'
            
        except Exception as e:
            result = 'Error'
            self.logger.warning(f'Test {test_id} encountered an error: {e}')

        return result

    def audit_filesystem_integrity_regularly_checked(self, test_id, **kwargs) -> Literal['Pass', 'Fail', 'Error']:
        result = 'Fail'

        try:
            cmd = 'grep -r aide /etc/cron.* /etc/crontab /var/spool/cron/root /etc/anacrontab'
            r1 = shellexec(cmd)

            if r1.stdout[0] != '':
                result = 'Pass'

            elif all([self.audit_service_is_enabled(test_id, service='aidecheck.service') == 'Pass',
                     self.audit_service_is_enabled(test_id, service='aidecheck.timer') == 'Pass',
                     self.audit_service_is_active(test_id, service='aidecheck.timer') == 'Pass']):
                result = 'Pass'

        except Exception as e:
            result = 'Error'
            self.logger.warning(f'Test {test_id} errored with error: {e}')

        return result

    pass


### Functions ###
def parse_arguments(argv=argv) -> Namespace:
    description = "This script runs tests on the system to check for compliance against the CIS CentOS 7 Benchmarks. No changes are made to system files by this script."
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
    version_str = f'{path.basename(__file__)} {__version__} ({__revision__})'

    parser = ArgumentParser(description=description, epilog=epilog, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--level', action='store', choices=level_choices, default=0, type=int,
                        help='Run tests for the specified level only')
    parser.add_argument('--include', action='store', nargs='+', dest='includes',
                        help='Space delimited list of tests to include')
    parser.add_argument('--exclude', action='store', nargs='+', dest='excludes',
                        help='Space delimited list of tests to exclude')
    parser.add_argument('-l', '--log-level', action='store', choices=log_level_choices, default='DEBUG',
                        help='Set log output level')
    parser.add_argument('--debug', action='store_const', const='DEBUG', dest='log_level',
                        help='Run script with debug output turned on. Equivalent to --log-level DEBUG')
    parser.add_argument('--nice', action='store_true', default=True,
                        help='Lower the CPU priority for test execution. This is the default behaviour.')
    parser.add_argument('--no-nice', action='store_false', dest='nice',
                        help='Do not lower CPU priority for test execution. This may make the tests complete faster but at the cost of putting a higher load on the server. Setting this overrides the --nice option.')
    parser.add_argument('--no-colour', '--no-color', action='store_true',
                        help='Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.')
    parser.add_argument('-V', '--version', action='version', version=version_str,
                        help='Print version and exit')

    args = parser.parse_args(argv[1:])

    logger = logging.getLogger(__name__)
    
    ## --log-level
    if args.log_level == 'DEBUG':
        logger.setLevel(level=args.log_level)
        logger.debug('Debugging enabled')

    ## --nice
    if args.nice:
        logger.debug("Tests will run with reduced CPU priority")

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

    return args


def shellexec(command) -> Namespace:  # pragma: no cover
    """Execute shell command on the system. Supports piped commands

    Parameters
    ----------
    command : string, required
        Shell command to execute

    Returns
    -------
    Namespace:

    """

    commands = command.split(' | ')

    try:
        for count, cmd in enumerate(commands):
            if count == 0:
                proc = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                proc = subprocess.Popen(cmd.split(" "), stdin=proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
        result = proc.communicate()

        output = result[0].decode('UTF-8').split('\n')
        error = result[1].decode('UTF-8').split('\n')
        returncode = proc.returncode

    except subprocess.CalledProcessError as e:
        result = e

        output = result.stdout.decode('UTF-8').split('\n')
        error = result.stderr.decode('UTF-8').split('\n')
        returncode = result.returncode

    except FileNotFoundError as e:
        output = ''.split('\n')
        error = e.args[1].split('\n')
        returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def main():  # pragma: no cover
    config = parse_arguments()
    audit = CISAudit(config=config)

    host_os = 'centos7'
    benchmarks_version = '3.0.0'
    results = []
    test_matrix = {
        'centos7': {
            '3.0.0': [
                ('1', 0, audit.header, 'Initial Setup', {}),
                ('1.1', 0, audit.header, 'Filesystem Configuration', {}),
                ('1.1.1', 0, audit.header, 'Disable unused filesystems', {}),
                ('1.1.1.1', 1, audit.audit_filesystem_is_disabled, 'Ensure mounting of cramfs is disabled', {'filesystems': ['cramfs']}),
                ('1.1.1.2', 2, audit.audit_filesystem_is_disabled, 'Ensure mounting of squashfs is disabled', {'filesystems': ['squashfs']}),
                ('1.1.1.3', 1, audit.audit_filesystem_is_disabled, 'Ensure mounting of udf is disabled', {'filesystems': ['udf']}),
                ('1.1.1.4', 1, audit.audit_filesystem_is_disabled, 'Ensure mounting of FAT is limited', {'filesystems': ['fat', 'vfat', 'msdos']}),
                ('1.1.2', 1, audit.audit_partition_is_separate, 'Ensure /tmp is configured', {'partition': '/tmp'}),
                ('1.1.3', 1, audit.audit_partition_option_is_set, 'Ensure noexec option set on /tmp partition', {'option': 'noexec', 'partition': '/tmp'}),
                ('1.1.4', 1, audit.audit_partition_option_is_set, 'Ensure nodev option set on /tmp partition', {'option': 'nodev', 'partition': '/tmp'}),
                ('1.1.5', 1, audit.audit_partition_option_is_set, 'Ensure nosuid option set on /tmp partition', {'option': 'nosuid', 'partition': '/tmp'}),
                ('1.1.6', 1, audit.audit_partition_is_separate, 'Ensure /tmp is configured', {'partition': '/tmp'}),
                ('1.1.7', 1, audit.audit_partition_option_is_set, 'Ensure noexec option set on /dev/shm partition', {'option': 'noexec', 'partition': '/dev/shm'}),
                ('1.1.8', 1, audit.audit_partition_option_is_set, 'Ensure nodev option set on /dev/shm partition', {'option': 'nodev', 'partition': '/dev/shm'}),
                ('1.1.9', 1, audit.audit_partition_option_is_set, 'Ensure nosuid option set on /dev/shm partition', {'option': 'nosuid', 'partition': '/dev/shm'}),
                ('1.1.10', 1, audit.audit_partition_is_separate, 'Ensure separate partition exists for /var', {'partition': '/var'}),
                ('1.1.11', 1, audit.audit_partition_is_separate, 'Ensure separate partition exists for /var/tmp', {'partition': '/var/tmp'}),
                ('1.1.12', 1, audit.audit_partition_option_is_set, 'Ensure noexec option set on /var/tmp partition', {'option': 'noexec', 'partition': '/var/tmp'}),
                ('1.1.13', 1, audit.audit_partition_option_is_set, 'Ensure nodev option set on /var/tmp partition', {'option': 'nodev', 'partition': '/var/tmp'}),
                ('1.1.14', 1, audit.audit_partition_option_is_set, 'Ensure nosuid option set on /var/tmp partition', {'option': 'nosuid', 'partition': '/var/tmp'}),
                ('1.1.15', 1, audit.audit_partition_is_separate, 'Ensure separate partition exists for /var/log', {'partition': '/var/log'}),
                ('1.1.16', 1, audit.audit_partition_is_separate, 'Ensure separate partition exists for /var/log/audit', {'partition': '/var/log/audit'}),
                ('1.1.17', 2, audit.audit_partition_is_separate, 'Ensure separate partition exists for /home', {'partition': '/home'}),
                ('1.1.18', 1, audit.audit_partition_option_is_set, 'Ensure nodev option set on /home partition', {'option': 'nodev', 'partition': '/home'}),
                ('1.1.19', 1, audit.manually, 'Ensure noexec option set on removable media partitions', {}),
                ('1.1.20', 1, audit.manually, 'Ensure nodev option set on removable media partitions', {}),
                ('1.1.21', 1, audit.manually, 'Ensure nosuid option set on removable media partitions', {}),
                ('1.1.22', 1, audit.audit_sticky_bit_on_world_writable_dirs, 'Ensure sticky bit is set on all world-writable directories', {}),
                ('1.1.23', 1, audit.audit_service_is_disabled, 'Disable Automounting', {'service': 'autofs'}),
                ('1.1.24', 1, audit.audit_filesystem_is_disabled, 'Disable USB Storage', {'filesystems': 'usb-storage'}),

                ('1.2', 0, audit.header, 'Configure Software Updates', {}),
                ('1.2.1', 1, audit.manually, 'Ensure GPG keys are configured', {}),
                ('1.2.2', 1, audit.manually, 'Ensure package manager repositories are configured', {}),
                ('1.2.3', 1, audit.audit_gpgcheck_is_activated, 'Ensure gpgcheck is globally activated', {}),

                ('1.3', 0, audit.header, 'Configure sudo', {}),
                ('1.3.1', 1, audit.audit_package_is_installed, 'Ensure sudo is installed', {'package': 'sudo'}),
                ('1.3.2', 1, audit.audit_sudo_commands_use_pty, 'Ensure sudo commands use pty', {}),
                ('1.3.3', 1, audit.audit_sudo_log_exists, 'Ensure sudo log file exists', {}),

                ('1.4', 0, audit.header, 'Filesystem Integrity Checking', {}),
                ('1.4.1', 1, audit.audit_package_is_installed, 'Ensure AIDE is installed', {'package': 'aide'}),
                ('1.4.2', 1, audit.audit_filesystem_integrity_regularly_checked, 'Ensure filesystem integrity is regularly checked', {}),

            ],
        }
    }
    
    for test in test_matrix[host_os][benchmarks_version]:
        test_id = test[0]
        test_level = test[1]
        test_function = test[2]
        test_description = test[3]
        kwargs = test[4]
        
        if audit.test_is_included(test_id, test_level):
            start_time = datetime.now()
            #result = audit.run_test(id, level, function, **kwargs)
            result = test_function(test_id, **kwargs)
            end_time = datetime.now()
            duration = f'{int((end_time.microsecond - start_time.microsecond) / 1000)}ms'

            ## "ID,Description,Scoring,Level,Result,Duration"
            if result == 'Header':
                results.append([test_id, test_description])
            else:
                results.append([test_id, test_description, test_level, result, duration])

    for result in results:
        print(result)


if __name__ == '__main__':  # pragma: no cover
    main()
