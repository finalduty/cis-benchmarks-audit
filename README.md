# CIS Benchmarks Audit

This repo contains a bash script which performs tests against your CentOS system to give an indication of whether the running server may compliy with the CIS Benchmarks. https://learn.cisecurity.org/benchmarks

_Please note that only CentOS 7 is supported at this time._

### How do I use this script?
Download:

    curl -LO https://raw.githubusercontent.com/finalduty/cis_benchmarks_audit/master/cis-audit.sh && chmod 750 cis-audit.sh

Run: 
```
# ./cis-audit.sh --help
This script runs tests on the system to check for compliance against the CIS CentOS 7 Benchmarks.
No changes are made to system files by this script.

  Options:
    -h,  --help                  Prints this help text
         --debug                 Run script with debug output turned on
         --level (1,2)           Run tests for the specified level only
         --include "<test_ids>"  Space delimited list of tests to include
         --exclude "<test_ids>"  Space delimited list of tests to exclude
         --nice                  Lowers the CPU priority of executing tests
         --no-colour             Disable colouring for STDOUT (Note that output redirected to a file/pipe is never coloured)

  Examples:
  
    Run with debug enabled:
      cis-audit.sh --debug
      
    Exclude tests from section 1.1 and 1.3.2:
      cis-audit.sh --exclude "1.1 1.3.2"
      
    Include tests only from section 4.1 but exclude tests from section 4.1.1:
      cis-audit.sh --include 4.1 --exclude 4.1.1
    
    Run only level 1 tests
      cis-audit.sh --level 1
    
    Run level 1 tests and include some but not all SELinux questions
      cis-audit.sh --level 1 --include 1.6 --exclude 1.6.1.2

```

### Example Results
```
# ./cis-audit.sh --include 5.2
[00:00:01] (✓) 14 of 14 tests completed 

 CIS CentOS 7 Benchmark v2.1.1 Results 
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

### Notes / Caveats
#### Tests 4.1.4 to 4.1.17
The way that the tests are described in v2.2.0 of the standard do not directly reflect what is returned when querying the system. As such, the 'expected' output for these tests differs slightly to what is defined in the standard.

Users will find that when applying recommended configurations per the standard, that the verify command displays it slightly differently. For instance, in in `4.1.4`, when applying the recommendations as below:
```
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
```

The output from `auditctl -l` actually shows:
```
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change
```

####Test 4.1.8 & 4.1.9
The way the v2.2.0 standard lists the requirements to pass `4.1.8` and `4.1.9` conflicts with each other when looking at the 'logins' terms used.

This tool deviates from the standard here and includes the 'logins' portions of `4.1.9` in `4.1.8` instead. It is anticipated that users going for compliance against these two recommendations would do so at the same time and should not notice any difference between the implementation and the standard.

#### Disclaimer:
This is not a replacement for a full audit and a passing result from this script does not necessarily mean that you are compliant (but it should give you a good idea of where to start).  

The script will never make changes to your system, but it will write temporary data to to /tmp/.cis-audit* (which is cleaned up afterwards).  

This script can run multiple tests at a time and it is possible that some tests could have an adverse impact on your system(s). There is an adjustable limit for the number of concurrent tests as well as a nicing argument which can help keep load down.  

It is recommended that you **do not run this on a production server** at this time.  

_No warranty is offered and no responsibility will be taken for damage to systems resulting from the use of this script._