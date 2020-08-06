# CIS Benchmarks Audit

This repo contains a bash script which performs tests against your CentOS system to give an indication of whether the running server may compliy with the CIS v2.2.0 Benchmarks for CentOS. https://learn.cisecurity.org/benchmarks

_Only CentOS 7 is supported at this time._

### How do I use this?
#### Download:

    curl -LO https://raw.githubusercontent.com/finalduty/cis_benchmarks_audit/master/cis-audit.sh && chmod 750 cis-audit.sh

#### Run: 
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
         --output-json           output the results to the terminal for json
         --nice                  Lowers the CPU priority of executing tests
         --no-colour             Disable colouring for STDOUT (Note that output redirected to a file/pipe is never coloured)

  Examples:
  
    Exclude tests from section 1.1 and 1.3.2:
      cis-audit.sh --exclude "1.1 1.3.2"
      
    Include tests only from section 4.1 but exclude tests from subsection 4.1.1:
      cis-audit.sh --include 4.1 --exclude 4.1.1
    
    Run only level 1 tests
      cis-audit.sh --level 1
    
    Run level 1 tests and include some but not all SELinux questions
      cis-audit.sh --level 1 --include 1.6 --exclude 1.6.1.2

    Email output to email@example.com
      cis-audit.sh --level 1 | mail -s "CIS Audit Report on $HOSTNAME" email@example.com
      
    Display only Failed tests
      cis-audit.sh --level 1 | grep Fail

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

### Notes / Caveats
#### Test 3.7
> _3.7 - Ensure wireless interfaces are disabled (Not Scored)_  

This test deviates from the audit steps specified in the standard. The assumption here is that if you are on a server then you shouldn't have the `wireless-tools` package installed so you wouldn't even be able to use any wireless interfaces, and if you're on a laptop, you almost certainly do want wireless access.

#### Tests 4.1.4 to 4.1.17
> _4.1.4 - Ensure events that modify date and time information are collected (Scored)_  
> _4.1.5 - Ensure events that modify user/group information are collected (Scored)_  
> _4.1.6 - Ensure events that modify the system's network environment are collected (Scored)_  
> _4.1.7 - Ensure events that modify the system's Mandatory Access Controls are collected (Scored)_  
> _4.1.8 - Ensure login and logout events are collected (Scored)_  
> _4.1.9 - Ensure session initiation information is collected (Scored)_  
> _4.1.10 - Ensure discretionary access control permission modification events are collected (Scored)_  
> _4.1.11 - Ensure unsuccessful unauthorized file access attempts are collected (Scored)_  
> _4.1.12 - Ensure use of privileged commands is collected (Scored)_  
> _4.1.13 - Ensure successful file system mounts are collected (Scored)_  
> _4.1.14 - Ensure file deletion events by users are collected (Scored)_  
> _4.1.15 - Ensure changes to system administration scope (sudoers) is collected (Scored)_  
> _4.1.16 - Ensure system administrator actions (sudolog) are collected (Scored)_  
> _4.1.17 - Ensure kernel module loading and unloading is collected (Scored)_  

The way that the tests are described in v2.2.0 of the standard do not directly reflect what is returned when querying the system. As such, the 'expected' output for these tests differs slightly to what is defined in the standard.

Users will find that when applying the recommended configurations per the standard, that the verify command displays it slightly differently. For instance, in `4.1.4`, when applying the recommendations as below:
```
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
```

The output from `auditctl -l` actually shows:
```
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change
```

#### Tests 4.1.8 & 4.1.9
> _4.1.8 - Ensure login and logout events are collected (Scored)_  
> _4.1.9 - Ensure session initiation information is collected (Scored)_  

The way the v2.2.0 standard lists the requirements to pass `4.1.8` and `4.1.9` conflicts with each other when looking at the 'logins' terms used.

This tool deviates from the standard here and includes the 'logins' portions of `4.1.9` in the tests for `4.1.8` instead of the ones specified in the standard. It is anticipated that users going for compliance against these two recommendations would do so at the same time and therefore should not notice any difference between the test results and the standard.

#### Test 5.4.4 
The standard recommends that umask permissions be set to 027 or higher. Currently this test only checks for 027, so a more restrictive umask such as 077 would fail. Further, it does not test the /etc/profile/*.sh files on the system.

I will leave it this way until someone needs a more restrictive umask test - Just add an issue if this is you 👍

### Disclaimer:
This is not a replacement for a full audit and a passing result from this script does not necessarily mean that you are compliant (but it should give you a good idea of where to start).  

The script will never make changes to your system, but it will write temporary data to to /tmp/.cis-audit* (which is cleaned up afterwards).  

This script can run multiple tests at a time and it is possible that some tests could have an adverse impact on your system(s). There is an adjustable limit for the number of concurrent tests as well as a nicing argument which can help keep load down.  

_No warranty is offered and no responsibility will be taken for damage to systems resulting from the use of this script._