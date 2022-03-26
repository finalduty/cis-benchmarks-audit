# CIS Benchmarks Audit
<p>
  <a href="https://github.com/finalduty/cis-benchmarks-audit/tags">
    <img alt="Latest version" src="https://img.shields.io/github/v/tag/finalduty/cis-benchmarks-audit?include_prereleases&label=latest&logo=python">
  </a>
  <a href="https://github.com/finalduty/cis-benchmarks-audit/actions/workflows/ci_tests.yml">
    <img alt="GitHub Actions" src="https://github.com/finalduty/cis-benchmarks-audit/actions/workflows/ci_tests.yml/badge.svg">
  </a>
  <a href="https://github.com/finalduty/cis-benchmarks-audit/blob/main/LICENSE">
    <img alt="License Apache-2.0" src="https://img.shields.io/github/license/finalduty/cis-benchmarks-audit">
  </a>
  <a href="https://codecov.io/gh/finalduty/cis-benchmarks-audit">
    <img src="https://codecov.io/gh/finalduty/cis-benchmarks-audit/branch/main/graph/badge.svg?token=BAFVN48B40"/>
  </a>
  <a href="https://www.codefactor.io/repository/github/finalduty/cis-benchmarks-audit/badge">
    <img alt="CodeFactor" src="https://www.codefactor.io/repository/github/finalduty/cis-benchmarks-audit/badge">
  </a>
  <a href="https://github.com/psf/black">
    <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg">
  </a>
</p>

This repo contains a python3 script which audits for conformance of your system against the CIS Hardening Benchmarks

**Supported Versions:**
OS|Benchmark Versions|Python Version
---|---|---
CentOS 7|3.1.2|3.6

https://www.cisecurity.org/cis-securesuite/cis-securesuite-membership-terms-of-use/
### How do I use this?
#### Download:

    curl -LO https://raw.githubusercontent.com/finalduty/cis_benchmarks_audit/main/cis_audit.py && chmod 750 cis_audit.py

#### Run: 
```
#usage: cis_audit.py [-h] [--level {1,2}] [--include INCLUDES [INCLUDES ...]]
                    [--exclude EXCLUDES [EXCLUDES ...]]
                    [-l {DEBUG,INFO,WARNING,CRITICAL}] [--debug] [--nice]
                    [--no-nice] [--no-colour]
                    [--system-type {server,workstation}] [--server]
                    [--workstation] [--outformat {csv,json,psv,text,tsv}]
                    [--text] [--json] [--csv] [--psv] [--tsv] [-V] [-c CONFIG]

This script runs tests on the system to check for compliance against the CIS Benchmarks. No changes are made to system files by this script.

optional arguments:
  -h, --help            show this help message and exit
  --level {1,2}         Run tests for the specified level only
  --include INCLUDES [INCLUDES ...]
                        Space delimited list of tests to include
  --exclude EXCLUDES [EXCLUDES ...]
                        Space delimited list of tests to exclude
  -l {DEBUG,INFO,WARNING,CRITICAL}, --log-level {DEBUG,INFO,WARNING,CRITICAL}
                        Set log output level
  --debug               Run script with debug output turned on. Equivalent to --log-level DEBUG
  --nice                Lower the CPU priority for test execution. This is the default behaviour.
  --no-nice             Do not lower CPU priority for test execution. This may make the tests complete faster but at the cost of putting a higher load on the server. Setting this overrides the --nice option.
  --no-colour, --no-color
                        Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.
  --system-type {server,workstation}
                        Set which test level to reference
  --server              Use "server" levels to determine which tests to run. Equivalent to --system-type server [Default]
  --workstation         Use "workstation" levels to determine which tests to run. Equivalent to --system-type workstation
  --outformat {csv,json,psv,text,tsv}
                        Output type for results
  --text                Output results as text. Equivalent to --output text [default]
  --json                Output results as json. Equivalent to --output json
  --csv                 Output results as comma-separated values. Equivalent to --output csv
  --psv                 Output results as pipe-separated values. Equivalent to --output psv
  --tsv                 Output results as tab-separated values. Equivalent to --output tsv
  -V, --version         Print version and exit
  -c CONFIG, --config CONFIG
                        Location of config file to load

Examples:
    
    Run with debug enabled:
    ./cis_audit.py --debug
        
    Exclude tests from section 1.1 and 1.3.2:
    ./cis_audit.py --exclude 1.1 1.3.2
        
    Include tests only from section 4.1 but exclude tests from section 4.1.1:
    ./cis_audit.py --include 4.1 --exclude 4.1.1
        
    Run only level 1 tests
    ./cis_audit.py --level 1
        
    Run level 1 tests and include some but not all SELinux questions
    ./cis_audit.py --level 1 --include 1.6 --exclude 1.6.1.2

```

### Example Results
```
# ./cis-audit.sh --include 5.2
[00:00:01] (✓) 14 of 14 tests completed 

 CIS CentOS 7 Benchmark v2.2.0 Results 
---------------------------------------
ID      Description                                                Scoring  Level  Result  Duration
--      -----------                                                -------  -----  ------  --------

5       Access Authentication and Authorization
5.2     SSH Server Configuration
5.2.1   Ensure permissions on /etc/ssh/sshd_config are configured  Scored   1      Pass    33ms
5.2.2   Ensure SSH Protocol is set to 2                            Scored   1      Pass    5ms
5.2.3   Ensure SSH LogLevel is set to INFO                         Scored   1      Pass    6ms
5.2.4   Ensure SSH X11 forwarding is disabled                      Scored   1      Pass    4ms
5.2.5   Ensure SSH MaxAuthTries is set to 4 or less                Scored   1      Pass    9ms
5.2.6   Ensure SSH IgnoreRhosts is enabled                         Scored   1      Pass    5ms
5.2.7   Ensure SSH HostbasedAuthentication is disabled             Scored   1      Pass    5ms
5.2.8   Ensure SSH root login is disabled                          Scored   1      Fail    8ms
5.2.9   Ensure SSH PermitEmptyPasswords is disabled                Scored   1      Pass    5ms
5.2.10  Ensure SSH PermitUserEnvironment is disabled               Scored   1      Pass    8ms
5.2.11  Ensure only approved ciphers are used                      Scored   1      Pass    16ms
5.2.12  Ensure only approved MAC algorithms are used               Scored   1      Pass    45ms
5.2.13  Ensure SSH Idle Timeout Interval is configured             Scored   1      Fail    15ms
5.2.14  Ensure SSH LoginGraceTime is set to one minute or less     Scored   1      Pass    11ms
5.2.15  Ensure SSH access is limited                               Skipped  1              
5.2.16  Ensure SSH warning banner is configured                    Scored   1      Pass    6ms

Passed 13 of 15 tests in 1 seconds (1 Skipped, 0 Errors)
```


### Disclaimer:
This is not a replacement for a full audit and a passing result from this script does not necessarily mean that you are compliant (but it should give you a good idea of where to start).  

The script will never make changes to your system.

This script can run multiple tests at a time and it is possible that some tests could have an adverse impact on your system(s). There is an adjustable limit for the number of concurrent tests as well as a nicing argument which can help keep load down.  

_No warranty is offered and no responsibility will be taken for damage to systems resulting from the use of this script._
