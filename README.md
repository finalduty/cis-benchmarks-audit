# CIS Benchmarks Audit

This repo contains a bash script which performs tests against your CentOS system to give an indication of whether the running server may compliy with the CIS Benchmarks. https://learn.cisecurity.org/benchmarks

_Please note that only CentOS 7 is supported at this time._

### How do I use this script?
Download:

    curl -LO https://raw.githubusercontent.com/finalduty/cis_benchmarks_audit/master/cis-audit.sh&& chmod 750 cis-audit.sh

Run: 
```
# ./cis-audit.sh --help
This script runs tests on the system to check for compliance against the CIS CentOS 7 Benchmarks.
No changes are made to system files by this script.

  Options:
    -h,  --help                  Prints this help text
         --debug                 Run script with debug output turned on
         --include "<test_ids>"  Space delimited list of tests to include
         --exclude "<test_ids>"  Space delimited list of tests to exclude
         --nice                  Lowers the CPU priority of executing tests
         --no-colour             Disable colouring for STDOUT (Output redirected to a file/pipe is never coloured anyway)

  Examples:
  
    Run with debug enabled:
      audit.sh --debug
      
    Exclude tests from section 1.1 and 1.3.2:
      audit.sh --exclude "1.1 1.32"

    Include tests only from section 4.1 but exclude tests from section 4.1.1:
      audit.sh --include 4.1 --exclude 4.1.1
```

#### Disclaimer:
This is not a replacement for a full audit and a passing result from this script does not necessarily mean that you are compliant (but should give a good idea of where to start). The script will never make any changes to your system for you, but will write temporary state output to /tmp (which it will clean up afterwards).
This script can spawn multiple tests at a time making it possible that some tests could cause adverse effects to your server. There is an adjustable limit as well as a nicing argument which can help with this. In any case It is recommended that you **do not run this on a production server**.

_No warranty is offered and no responsibility will be taken for damage to systems resulting from the use of this script._