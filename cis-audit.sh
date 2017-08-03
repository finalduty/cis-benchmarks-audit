#!/bin/bash
## andy.dustin@gmail.com [rev: a42d1a0]
## This script checks for compliance against CIS CentOS Linux 7 Benchmark v2.1.1 01-31-2017 measures
## Each individual standard has it's own function and is forked to the background, allowing for 
## multiple tests to be run in parallel, reducing execution time.


### Variables ###
## This section defines global variables used in the script
args=$@
count=0
exit_code=0
me=$(basename $0)
result=Fail
state=0
tmp_file_base="/tmp/.cis_audit"
tmp_file="$tmp_file_base-$(date +%y%m%d%H%M%S).output"
started_counter="$tmp_file_base-$(date +%y%m%d%H%M%S).started.counter"
finished_counter="$tmp_file_base-$(date +%y%m%d%H%M%S).finished.counter"
wait_time="0.3"
progress_update_delay="0.1"
max_running_tests=10
debug=False
trace=False
renice_bool=False
renice_value=5
start_time=$(date +%s)
color=True


### Functions ###
## This section defines functions used in the script 
is_test_included() {
    id=$1
    
    [ $debug == "True" ] && write_debug "Checking whether to run test $id"
    
    ## Check if there were explicitly included tests
    if [ $(echo "$include" | wc -c ) -gt 3 ]; then
        
        ## Check if the $id is in the included tests
        if [ $(echo " $include " | grep -c " $id ") -gt 0 ]; then
            [ $debug == "True" ] && write_debug "Test $id was explicitly included"
        elif [ $(echo " $include " | grep -c " $id\.") -gt 0 ]; then
            [ $debug == "True" ] && write_debug "Test $id is the parent of an included test"
        elif [ $(for i in $include; do echo " $id" | grep " $i\."; done | wc -l) -gt 0 ]; then
            [ $debug == "True" ] && write_debug "Test $id is the child of an included test"
        else
            [ $debug == "True" ] && write_debug "Excluding test $id (Not found in the include list)"
            return 1
        fi
    fi
    
    ## If this $id was included in the tests check it wasn't then excluded
    if [ $(echo " $exclude " | grep -c " $id ") -gt 0 ]; then
        [ $debug == "True" ] && write_debug "Test $id was explicitly excluded"
        [ $debug == "True" ] && write_debug "Excluding test $id (Found in the include list)"
        return 1
    elif [ $(for i in $exclude; do echo " $id" | grep " $i\."; done | wc -l) -gt 0 ]; then
        [ $debug == "True" ] && write_debug "Test $id is the child of an excluded test"
        [ $debug == "True" ] && write_debug "Excluding test $id (Found in the exclude list)"
        return 1
    fi
    
    [ $debug == "True" ] && write_debug "Including test $id "
    
    return 0
} ## Checks whether to run a particular test or not
get_id() {
    echo $1 | sed -e 's/test_//' -e 's/\.x.*$//'
} ## Returns a prettied id for a calling function
help_text() {
    cat  << EOF |fmt -sw99
This script runs tests on the system to check for compliance against the CIS CentOS 7 Benchmarks.
No changes are made to system files by this script.

  Options:
EOF

    cat << EOF | column -t -s'|'
||-h,|--help|Prints this help text
|||--debug|Run script with debug output turned on
|||--include "<test_ids>"|Space delimited list of tests to include
|||--exclude "<test_ids>"|Space delimited list of tests to exclude
|||--nice|Lowers the CPU priority of executing tests
|||--no-colour|Disable colouring for STDOUT (Note that output redirected to a file/pipe is never coloured)

EOF

    cat << EOF

  Examples:
  
    Run with debug enabled:
      $me --debug
      
    Exclude tests from section 1.1 and 1.3.2:
      $me --exclude "1.1 1.3.2"

    Include tests only from section 4.1 but exclude tests from section 4.1.1:
      $me --include 4.1 --exclude 4.1.1

EOF

exit 0

} ## Outputs help text
now() {
    echo $(( $(date +%s%N) / 1000000 ))
} ## Short function to give standardised time for right now (saves updating the date method everywhere)
outputter() {
    [ $debug == "True" ] && write_debug "Formatting and writing results to STDOUT"
    echo
    echo " CIS CentOS 7 Benchmark v2.1.1 Results "
    echo "---------------------------------------"

    if [ -t 1 -a $color == "True" ]; then
        (
        echo "ID,Description,Scoring,Level,Result,Duration"
        echo "--,-----------,-------,-----,------,--------"
        sort -V $tmp_file
        ) | column -t -s , |\
            sed -e $'s/^[0-9]\s.*$/\\n\e[1m&\e[22m/' \
                -e $'s/^[0-9]\.[0-9]\s.*$/\e[1m&\e[22m/' \
                -e $'s/\sFail\s/\e[31m&\e[39m/' \
                -e $'s/\sPass\s/\e[32m&\e[39m/' \
                -e $'s/^.*\sSkipped\s.*$/\e[2m&\e[22m/'
            
    else
        (
        echo "ID,Description,Scoring,Level,Result,Duration"
        sort -V $tmp_file
        ) | column -t -s , | sed -e '/^[0-9]\ / s/^/\n/'
    fi

    tests_total=$(egrep -c "Scored|Skipped" $tmp_file)
    tests_skipped=$(grep -c ",Skipped," $tmp_file)
    tests_ran=$(( $tests_total - $tests_skipped ))
    tests_passed=$(egrep -c ",Pass," $tmp_file)
    tests_failed=$(egrep -c ",Fail," $tmp_file)
    
    echo
    echo "Passed $tests_passed of $tests_ran tests ($tests_skipped Skipped)"
    echo

#    cat << EOF | column -t -s , | sed '/^[0-9]\ / s/^/\n/'
#ID,Description,Scoring,Level,Result,Duration
#$(sort -V $tmp_file)
#EOF
    [ $debug == "True" ] && write_debug "All results written to STDOUT"
} ## Prettily prints the results to the terminal
parse_args() {
    args=$@
    
    ## Call help_text function if -h or --help present
    $(echo $args | egrep -- '-h' &>/dev/null) && help_text
    
    ## Check arguments for --debug
    $(echo $args | grep -- '--debug' &>/dev/null)  &&   debug="True" || debug="False"
    [ $debug == "True" ] && write_debug "Debug enabled"
    
    ## Full noise output
    $(echo $args | grep -- '--trace' &>/dev/null) &&  trace="True" && set -x
    [ $trace == "True" ] && write_debug "Trace enabled"
    
    ## Renice / lower priority of script execution
    $(echo $args | grep -- '--nice' &>/dev/null)  &&   renice_bool="True" || renice_bool="False"
    [ $renice_bool == "True" ] && write_debug "Tests will run with reduced execution priority"
    
    ## Disable colourised output
    $(echo $args | egrep -- '--no-color|--no-colour' &>/dev/null)  &&   color="False" || color="True"
    [ $color == "False" ] && write_debug "Coloured output disabled"
    
    ## Check arguments for --exclude
    ## NB: The whitespace at the beginning and end is required for the greps later on
    exclude=" $(echo "$args" | sed -e 's/^.*--exclude //' -e 's/--.*$//') "
    if [ $(echo "$exclude" | wc -c ) -gt 3 ]; then
        [ $debug == "True" ] && write_debug "Exclude list is populated \"$exclude\""
    else
        [ $debug == "True" ] && write_debug "Exclude list is empty"
    fi
    
    ## Check arguments for --include
    ## NB: The whitespace at the beginning and end is required for the greps later on
    include=" $(echo "$args" | sed -e 's/^.*--include //' -e 's/--.*$//') "
    if [ $(echo "$include" | wc -c ) -gt 3 ]; then
        [ $debug == "True" ] && write_debug "Include list is populated \"$include\""
    else
        [ $debug == "True" ] && write_debug "Include list is empty"
    fi
    
} ## Parse arguments passed in to the script
progress() {
    ## We don't want progress output while we're spewing debug or trace output
    [ $debug == "True" ] && write_debug "Not displaying progress ticker while debug is enabled" && return 0
    [ $trace == "True" ] && return 0
    
    array=(\| \/ \- \\)
    
    while [ $(running_children) -gt 1 ]; do 
        started=$(cat $started_counter)
        finished=$(cat $finished_counter)
        running=$(( $started - $finished ))
        
        tick=$(( $tick + 1 ))
        pos=$(( $tick % 4 ))
        char=${array[$pos]}
        
        script_duration="$(date +%T -ud @$(( $(date +%s) - $start_time )))"
        printf "\r[$script_duration] ($char) $finished of $started tests completed " >&2
        
        sleep $progress_update_delay
    done
    
    ## When all tests have finished, make a final update
    finished=$(cat $finished_counter)
    script_duration="$(date +%T -ud @$(( $(date +%s) - $start_time )))"
    #printf "\r[✓] $finished of $finished tests completed\n" >&2
    printf "\r[$script_duration] (✓) $started of $started tests completed\n" >&2
} ## Prints a pretty progress spinner while running tests
run_test() {
    id=$1
    test=$2
    args=$(echo $@ | awk '{$1 = $2 = ""; print $0}' | sed 's/^ *//')
    
    if [ $(is_test_included $id; echo $?) -eq 0 ]; then
        [ $debug == "True" ] && write_debug "Requesting test $id by calling \"$test $id $args &\""
        
        while [ "$(pgrep -P $$ 2>/dev/null | wc -l)" -ge $max_running_tests ]; do 
            [ $debug == "True" ] && write_debug "There were already max_running_tasks ($max_running_tests) while attempting to start test $id. Pausing for $wait_time seconds"
            sleep $wait_time
        done
        
        [ $debug == "True" ] && write_debug "There were $(( $(pgrep -P $$ 2>&1 | wc -l) - 1 ))/$max_running_tests max_running_tasks when starting test $id."
        
        $test $id $args &
    fi
    
    return 0
} ## Compares test id against includes / excludes list and returns whether to run test or not
running_children() {
    ## Originally tried using pgrep, but it returned one line even when output was "empty"
    search_terms="PID|ps$|grep$|wc$|sleep$"

    [ $debug == True ] && ps --ppid $$ | egrep -v "$search_terms"
    ps --ppid $$ | egrep -v "$search_terms" | wc -l
} ## Ghetto implementation that returns how many child processes are running
setup() {
    [ $debug == "True" ] && write_debug "Script was started with PID: $$"
    if [ $renice_bool = "True" ]; then
        if [ $renice_value -gt 0 -a $renice_value -le 19 ]; then
            renice_output="$(renice +$renice_value $$)"
            [ $debug == "True" ] && write_debug "Renicing $renice_output"
        fi
    fi
    
    [ $debug == "True" ] && write_debug "Creating tmp files with base $tmp_file_base*"
    cat /dev/null > $tmp_file
    echo 0 > $started_counter
    echo 0 > $finished_counter
} ## Sets up required files for test
test_start() {
    id=$1
    
    [ $debug == "True" ] && write_debug "Test $id started"
        
    echo $(( $(cat $started_counter) + 1 )) > $started_counter
    [ $debug == "True" ] && write_debug "Progress: $(cat $finished_counter)/$(cat $started_counter) tests."
    
    now
} ## Prints debug output (when enabled) and returns current time
test_finish() {
    id=$1
    start_time=$2
    
    duration="$(( $(now) - $start_time ))"
    [ $debug == "True" ] && write_debug "Test "$id" completed after "$duration"ms"
    
    echo $(( $(cat $finished_counter) + 1 )) > $finished_counter
    [ $debug == "True" ] && write_debug "Progress: $(cat $finished_counter)/$(cat $started_counter) tests."
    
    #progress_bar
    
    echo $duration
} ## Prints debug output (when enabled) and returns duration since $start_time
tidy_up() {
    [ $debug == "True" ] && opt="-v"
    rm $opt "$tmp_file_base"* &>2
} ## Tidys up files created during testing
write_cache() {
    [ $debug == "True" ] && write_debug "Writing to $tmp_file - $@"
    printf "$@\n" >> $tmp_file
} ## Writes additional rows to the output cache
write_debug() {
    printf "[DEBUG] $(date -Ins) $@\n" >&2
} ## Writes debug output to STDERR
write_err() {
    printf "[ERROR] $@\n" >&2
} ## Writes error output to STDERR
write_result() {
    [ $debug == "True" ] && write_debug "Writing result to $tmp_file - $@"
    echo $@ >> $tmp_file
} ## Writes test results to the output cache


### Benchmark Tests ###
## This section defines the benchmark tests that are called by the script

## Tests used in multiple sections
skip_test() {
    ## This function is a blank for any tests too complex to perform 
    ## or that rely too heavily on site policy for definition
    
    id=$1
    description=$( echo $@ | awk '{$1=""; print $0}' | sed 's/^ *//')
    scored="Skipped"
    result=""

    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_is_enabled() {
    id=$1
    service=$2
    name=$3
    description="Ensure $name service is enabled"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $( systemctl is-enabled $service ) == "enabled" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_is_installed() {
    id=$1
    pkg=$2
    name=$3
    description="Ensure $name is installed"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_perms() {
    id=$1
    perms=$2
    file=$3
    description="Ensure permissions on $file are configured"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    u=$(echo $perms | cut -c1)
    g=$(echo $perms | cut -c2)
    o=$(echo $perms | cut -c3 )
    file_perms="$(stat $file | awk '/Access: \(/ {print $2}')"
    file_u=$(echo $file_perms | cut -c3)
    file_g=$(echo $file_perms | cut -c4)
    file_o=$(echo $file_perms | cut -c5)
    
    [ "$(ls -l $file | awk '{ print $3" "$4 }')" == "root root" ] || state=1
    [ $file_u -le $u ] || state=1
    [ $file_g -le $g ] || state=1
    [ $file_o -le $o ] || state=1
    
    [ $state -eq 0 ]&& result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 1 - Initial Setup
test_1.1.1.x() {
    id=$1
    filesystem=$2
    description="Ensure mounting of $filesystem is disabled"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $(diff -qs <(modprobe -n -v $filesystem 2>/dev/null) <(echo "install /bin/true") &>/dev/null; echo $?) -ne 0 ] && state=$(( $state + 1 ))
        [ $(lsmod | grep $filesystem | wc -l) -ne 0 ] && state=$(( $state + 2 ))
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_1.1.x-check_partition() {
    id=$1
    partition=$2
    description="Ensure separate partition exists for $partition"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        mount | grep "$partition " &>/dev/null  && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_1.1.x-check_fs_opts() {
    id=$1
    partition=$2
    fs_opt=$3
    description="Ensure $fs_opt option set on $partition"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        mount | egrep "$partition .*,$fs_opt," &>/dev/null  && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_1.1.x-check_removable() {
    id=$1
    fs_opt=$2
    description="Ensure $fs_opt option set on removable media partitions"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        ## NB: Only usb media is supported at the moment. Need to investigate what 
        ##  difference a CDROM, etc. can make, but I've set it up ready to add 
        ##  another search term. You're welcome :)
        devices=$(lsblk -pnlS | awk '/usb/ {print $1}')
        filesystems=$(for device in "$devices"; do lsblk -nlp $device | egrep -v '^$device|[SWAP]' | awk '{print $1}'; done)
        
        for filesystem in $filesystems; do
            fs_without_opt=$(mount | grep "$filesystem " | grep -v $fs_opt &>/dev/null | wc -l)
            [ $fs_without_opt -ne 0 ]  && state=1
        done
            
        [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_1.1.21() {
    id=$1
    description="Ensure sticky bit is set on all world-writable dirs"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        dirs=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | wc -l)
        [ $dirs -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.1.22() {
    id=$1
    description="Disable Automounting"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        ## Check whether autofs is even installed first
        service=$(systemctl | awk '/autofs/ {print $1}')
        [ -n "$service" ] && systemctl is-enabled $service 
        [ $? -ne 0 ]  && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.2.1() {
    id=$1
    description="Ensure package manager repositories are configured"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        repolist=$(yum repolist 2>/dev/null)
        [ $(echo "$repolist" | egrep -c '^base/7/') -ne 0 -a $(echo "$repolist" | egrep -c '^updates/7/') -ne 0 ] && result="Pass"
    ## Tests End
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.2.2() {
    id=$1
    description="Ensure GPG keys are configured"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $(rpm -q gpg-pubkey | wc -l) -ne 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.2.3() {
    id=$1
    description="Ensure gpgcheck is globally activated"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $(grep -R ^gpgcheck=0 /etc/yum.conf /etc/yum.repos.d/ | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.3.2() {
    id=$1
    description="Ensure filesystem integrity is regularly checked"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $(grep -Rl 'aide' /var/spool/cron/root /etc/cron* 2>/dev/null | wc -l) -ne 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.4.2() {
    id=$1
    description="Ensure bootloader password is set"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ $(grep "^set superusers" /boot/grub2/grub.cfg | wc -l) -eq 0 ] && state=1
        [ $(grep "^password" /boot/grub2/grub.cfg | wc -l ) -eq 0 ] && state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.4.3() {
    id=$1
    description="Ensure authentication required for single user mode"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str='ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
        
        [ "$(grep /sbin/sulogin /usr/lib/systemd/system/rescue.service)" == "$str" ] || state=1
        [ "$(grep /sbin/sulogin /usr/lib/systemd/system/emergency.service)" == "$str" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.5.1() {
    id=$1
    description="Ensure core dumps are restricted"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str='ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
        
        [ "$(grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*)" == "* hard core 0" ] || state=1
        [ "$(sysctl fs.suid_dumpable)" == "fs.suid_dumpable = 0" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.5.2() {
    id=$1
    description="Ensure XD/NX support is enabled"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str='ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
        
        [ "$(dmesg | grep -o "NX (Execute Disable).*")" == "NX (Execute Disable) protection: active" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.5.3() {
    id=$1
    description="Ensure address space layout randomisation (ASLR) is enabled"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        str='ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
        
        [ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.5.4() {
    id=$1
    description="Ensure prelink is disabled"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str='ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
        
        [ "$(rpm -q prelink)" == "package prelink is not installed" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.1() {
    id=$1
    description="Ensure SELinux is not disabled in bootloader configuration"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
    
        [ $(grep "^\s*linux" /boot/grub2/grub.cfg | egrep 'selinux=0|enforcing=0' | wc -l) -eq 0 ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.2() {
    id=$1
    description="Ensure the SELinux state is enforcing"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ "$(grep SELINUX=enforcing /etc/selinux/config)" == "SELINUX=enforcing" ] || state=1
        [ "$(sestatus | awk '/Current mode/ {print $3}')" == "enforcing" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.3() {
    id=$1
    description="Ensure SELinux policy is configured"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ "$(grep SELINUXTYPE=targeted /etc/selinux/config)" == "SELINUXTYPE=targeted" ] || state=1
        [ "$(sestatus | awk '/Loaded policy name/ {print $4}')" == "targeted" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.4() {
    id=$1
    description="Ensure SETroubleshoot is not installed"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ "$(rpm -q setroubleshoot)" == "package setroubleshoot is not installed" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.5() {
    id=$1
    description="Ensure MCS Translation Service (mcstrans) is not installed"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ "$(rpm -q mcstrans)" == "package mcstrans is not installed" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.6.1.6() {
    id=$1
    description="Ensure no unconfined daemons exist"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ "$(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}' | wc -l)" -eq 0 ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.7.1.1() {
    id=$1
    description="Ensure message of the day is configured properly"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ $(wc -l /etc/motd | awk '{print $1}') -gt 1 ] || state=1
        [ $(egrep '(\\v|\\r|\\m|\\s)' /etc/motd | wc -l) -gt 0 ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.7.1.2() {
    id=$1
    description="Ensure local login warning banner is configured properly"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ $(wc -l /etc/issue | awk '{print $1}') -gt 1 ] || state=1
        [ $(egrep '(\\v|\\r|\\m|\\s)' /etc/issue | wc -l) -gt 0 ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.7.1.3() {
    id=$1
    description="Ensure remote login warning banner is configured properly"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        
        [ $(wc -l /etc/issue.net | awk '{print $1}') -gt 1 ] || state=1
        [ $(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net | wc -l) -gt 0 ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.7.1.4() {
    id=$1
    description="Ensure permissions on /etc/motd are configured"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str=$(ls -l /etc/motd)
        
        [ $(echo $str | awk '{print $1}') == "-rw-r--r--." ] || state=1
        [ $(echo $str | awk '{print $3}') == "root" ] || state=1
        [ $(echo $str | awk '{print $4}') == "root" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.7.2() {
    id=$1
    description="Ensure GDM login banner is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        state=0
        gdm_file="/etc/dconf/profile/gdm"
        banner_file="/etc/dconf/db/gdm.d/01-banner-message"
        
        if [ "$(rpm -q gdm)" != "package gdm is not installed" ]; then
            if [ -f $file ]; then
                diff -qs $file <( echo -e "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n") || state=1
            else
                state=2
            fi
            
            egrep '^banner-message-enable=true' $banner_file || state=4
            egrep '^banner-message-text=.*' $banner_file || state=8
        fi
        
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_1.8() {
    id=$1
    description="Ensure updates are installed"
    level=1
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(yum check-update &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 2 - Services
test_2.1.x() {
    id=$1
    service=$2
    description="Ensure $service services are not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        str=$(chkconfig --list 2>&1)
        state=0
        
        dgram="$(chkconfig --list $service-dgram 2>/dev/null | awk '{print $2}')"
        stream="$(chkconfig --list $service-stream 2>/dev/null | awk '{print $2}')"

        if [ "$dgram" != "" -o "$stream" != "" ]; then
            [ "$dgram" != "off" ] && state=1
            [ "$stream" != "off" ] && state=1
        fi
    
        [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.1.6() {
    id=$1
    description="Ensure tftp server is not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        str=$(chkconfig --list 2>&1)
        state=0
        
        if [ $(echo "$str" | egrep -c tftp) -gt 0 ]; then
            [ $(echo "$str" | awk '/tftp/ {print $2}') == "off" ] || state=1
        fi
    
        [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.1.7() {
    id=$1
    description="Ensure xinetd is not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(systemctl is-enabled xinetd) == "disabled" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_2.2.1.1() {
    id=$1
    description="Ensure time synchronisation is in use"
    level=1
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(rpm -q ntp &>/dev/null; echo $?) -eq 0 -o $(rpm -q chrony &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.1.2() {
    id=$1
    description="Ensure ntp is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $( rpm -q ntp &>/dev/null; echo $?) -eq 0 ]; then
        grep "^restrict -4 kod nomodify notrap nopeer noquery" /etc/ntpd.conf &>/dev/null || state=1
        grep "^restrict -6 kod nomodify notrap nopeer noquery" /etc/ntpd.conf &>/dev/null || state=2
        grep "^server .*$" /etc/ntpd.conf &>/dev/null || state=4
        [ -f /etc/systemd/system/ntpd.service ] && file="/etc/systemd/system/ntpd.service" || file="/usr/lib/systemd/system/ntpd.service"
        [ $(grep -c 'OPTIONS="-u ntp:ntp' /etc/sysconfig/ntpd) -ne 0 -o $(grep -c 'ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS' $file) -ne 0 ] || state=8
        
        [ $state -eq 0 ] && result="Pass"
        duration="$(test_finish $id $test_start_time)ms"
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##
    
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.1.3() {
    id=$1
    description="Ensure chrony is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $( rpm -q chrony &>/dev/null; echo $? ) -eq 0 ]; then
        grep "^server .*$" /etc/chrony.conf &>/dev/null || state=1
        if [ -f /etc/sysconfig/chronyd ]; then
            [ $( grep -c 'OPTIONS="-u chrony' /etc/sysconfig/chronyd ) -eq 0 ] && state=2
        else
            state=4
        fi
        
        [ $state -eq 0 ] && result="Pass"
        duration="$(test_finish $id $test_start_time)ms"
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##
    
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_2.2.2() {
    id=$1
    description="Ensure X Window System is not installed"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(rpm -qa xorg-x11* &>/dev/null | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.x() {
    id=$1
    pkg=$2
    service=$3
    port=$4
    name=$( echo $@ | awk '{$1=$2=$3=$4=""; print $0}' | sed 's/^ *//')
    description="Ensure $name is not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ]; then
        [ $(systemctl is-enabled $service) != "disabled" ] && state=1
        [ $(netstat -tupln | egrep ":$port " | wc -l) -ne 0 ] && state=2
    fi
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.7() {
    id=$1
    description="Ensure NFS and RPC are not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $(rpm -q nfs-utils &>/dev/null; echo $?) -eq 0 ]; then
        [ $(systemctl is-enabled nfs-server.service) == "disabled" ] && state=1
        [ $(netstat -tupln | egrep ":2049 " | wc -l) -ne 0 ] && state=2
    fi
    if [ $(rpm -q rpcbind &>/dev/null; echo $?) -eq 0 ]; then
        [ $(systemctl is-enabled rpcbind.socket) == "disabled" ] && state=4
        [ $(netstat -tupln | egrep ":111 " | wc -l) -ne 0 ] && state=8
    fi
    
    [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.15() {
    id=$1
    description="Ensure mail transfer agent is configured for local-only mode"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(netstat -tupln | egrep -v '127.0.0.1|::1:' | grep :25 | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_2.2.17() {
    id=$1
    description="Ensure NFS and RPC are not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $(rpm -q rsh &>/dev/null; echo $?) -eq 0 ]; then
        [ $(systemctl is-enabled rsh.socket) == "disabled" ] && state=1
        [ $(netstat -tupln | egrep ":514 " | wc -l) -ne 0 ] && state=2
        
        [ $(systemctl is-enabled rlogin.socket) == "disabled" ] && state=4
        [ $(netstat -tupln | egrep ":513 " | wc -l) -ne 0 ] && state=8
        
        [ $(systemctl is-enabled rexec.socket) == "disabled" ] && state=16
        [ $(netstat -tupln | egrep ":512 " | wc -l) -ne 0 ] && state=32
    fi
    
    [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_2.3.x() {
    id=$1
    pkg=$2
    name=$3
    description="Ensure $name client is not enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 3 - Network Configuration
test_3.x-single() {
    id=$1
    protocol=$2
    sysctl=$3
    val=$4
    description=$( echo $@ | awk '{$1=$2=$3=$4=""; print $0}' | sed 's/^ *//')
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ "$(sysctl net.$protocol.$sysctl)" == "net.$protocol.$sysctl = $val" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.x-double() {
    id=$1
    protocol=$2
    sysctl=$3
    val=$4
    description=$( echo $@ | awk '{$1=$2=$3=$4=""; print $0}' | sed 's/^ *//')
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ "$(sysctl net.$protocol.conf.all.$sysctl)" == "net.$protocol.conf.all.sysctl = $val" ] && state=1
        [ "$(sysctl net.$protocol.conf.default.$sysctl)" == "net.$protocol.conf.default.$sysctl = $val" ] && state=2
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.3.3() {
    id=$1
    description="Ensure IPv6 is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(modprobe -c | grep -c 'options ipv6 disable=1') -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.4.1() {
    id=$1
    description="Ensure TCP Wrappers is installed"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(rpm -q tcp_wrappers &>/dev/null; echo $? ) -eq 0 ] || state=1
        [ $(rpm -q tcp_wrappers-libs &>/dev/null; echo $? ) -eq 0 ] || state=2
        
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.4.2() {
    id=$1
    description="Ensure /etc/hosts.allow is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        if [ -f /etc/hosts.deny ]; then
            [ "$(grep -c '^ALL:' /etc/hosts.deny)" -gt 0 ] && result="Pass"
        fi
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.4.3() {
    id=$1
    description="Ensure /etc/hosts.deny is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        if [ -f /etc/hosts.deny ]; then
            [ "$(cat /etc/hosts.deny)" == "ALL: ALL" ] && result="Pass"
        fi
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.4.x() {
    id=$1
    file=$2
    description="Ensure permissions on $file are configured"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        state=0
        str=$(ls -l $file)
        
        [ $(echo $str | awk '{print $1}') == "-rw-r--r--." ] || state=1
        [ $(echo $str | awk '{print $3}') == "root" ] || state=1
        [ $(echo $str | awk '{print $4}') == "root" ] || state=1
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_3.5.x() {
    id=$1
    protocol=$2
    name=$3
    description="Ensure mounting of $name is disabled"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $(diff -qs <(modprobe -n -v $protocl 2>/dev/null) <(echo "install /bin/true") &>/dev/null; echo $?) -ne 0 ] && state=1
        [ $(lsmod | grep $protocol | wc -l) -ne 0 ] && state=2
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_3.6.2() {
    id=$1
    description="Ensure default deny firewall policy"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        str=$(iptables -S -w60)
        [ $(echo "$str" | grep -c -- "-P INPUT DROP") != 0 ] || state=1
        [ $(echo "$str" | grep -c -- "-P FORWARD DROP") != 0 ] || state=2
        [ $(echo "$str" | grep -c -- "-P OUTPUT DROP") != 0 ] || state=4
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_3.6.3() {
    id=$1
    description="Ensure loopback traffic is configured"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        str=$(iptables -S -w60)
        [ $(echo "$str" | grep -c -- "-A INPUT -i lo -j ACCEPT") != 0 ] || state=1
        [ $(echo "$str" | grep -c -- "-A OUTPUT -i lo -j ACCEPT") != 0 ] || state=2
        
        ## This check differs slightly from that specified in the standard. 
        ## I personally believe it's safer to specify that the rule is not on the loopback interface
        [ $(echo "$str" | grep -c -- "-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP") != 0 ] || state=4
        
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_3.6.4() {
    id=$1
    description="Ensure outbound and established connections are configured"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        str=$(iptables -S -w60)
        [ $(echo "$str" | grep -c -- "-A INPUT -m state --state ESTABLISHED -j ACCEPT") != 0 ] || state=1
        [ $(echo "$str" | grep -c -- "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT") != 0 ] || state=2
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
} 


## Section 4 - Logging and Auditing
test_4.1.1.1() {
    id=$1
    description="Ensure audit log storage size is configured"
    level=2
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $( egrep -c '^max_log_file = [0-9]*' /etc/audit/auditd.conf ) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.1.2() {
    id=$1
    description="Ensure system is disabled when audit logs are full"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $( grep -c '^space_left_action = email' /etc/audit/auditd.conf ) -eq 1 ] || state=1
        [ $( grep -c '^action_mail_acct = root' /etc/audit/auditd.conf ) -eq 1 ] || state=2
        [ $( grep -c '^admin_space_left_action = halt' /etc/audit/auditd.conf ) -eq 1 ] || state=4
        [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.1.3() {
    id=$1
    description="Ensure audit logs are not automatically deleted"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        [ $( grep -c '^max_log_file_action = keep_logs' /etc/audit/auditd.conf ) -eq 1 ] && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.1.2() {
    id=$1
    description="Ensure auditd service is enabled"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $( systemd is-enabled auditd ) == "enabled" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.3() {
    id=$1
    description="Ensure auditing for processes that start prior to auditd is enabled"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    linux_lines=$(grep -c "\slinux" /boot/grub2/grub.cfg)
    audit_lines=$(grep -c "\slinux.*audit=1" /boot/grub2/grub.cfg)
    [ $linux_lines -eq $audit_lines ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.4() {
    id=$1
    description="Ensure events that modify date and time information are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term=time-change
    expected='-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n
        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n
        -a always,exit -F arch=b64 -S clock_settime -k time-change\n
        -a always,exit -F arch=b32 -S clock_settime -k time-change\n
        -w /etc/localtime -p wa -k time-change'
        
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.5() {
    id=$1
    description="Ensure events that modify user/group information are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="identity"
    expected='-w /etc/group -p wa -k identity\n
        -w /etc/passwd -p wa -k identity\n
        -w /etc/gshadow -p wa -k identity\n
        -w /etc/shadow -p wa -k identity\n
        -w /etc/security/opasswd -p wa -k identity'
        
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.6() {
    id=$1
    description="Ensure events that modify the system's network environment are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="system-locale"
    expected='-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n
        -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale\n
        -w /etc/issue -p wa -k system-locale\n
        -w /etc/issue.net -p wa -k system-locale\n
        -w /etc/hosts -p wa -k system-locale\n
        -w /etc/sysconfig/network -p wa -k system-locale'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.7() {
    id=$1
    description="Ensure events that modify the system's Mandatory Access Controls are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="MAC-policy"
    expected='-w /etc/selinux/ -p wa -k MAC-policy'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.8() {
    id=$1
    description="Ensure login and logout events are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        search_term="logins"
        expected='-w /var/log/lastlog -p wa -k logins\n
            -w /var/run/faillock/ -p wa -k logins'
        
        diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.9() {
    id=$1
    description="Ensure session initiation information is collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="session"
    expected='-w /var/run/utmp -p wa -k session\n
        -w /var/log/wtmp -p wa -k session\n
        -w /var/log/btmp -p wa -k session'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.10() {
    id=$1
    description="Ensure discretionary access control permission modification events are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="perm_mod"
    expected='-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n
        -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n
        -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n
        -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n
        -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n
        -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.11() {
    id=$1
    description="Ensure unsuccessful unauthorised file access attempts are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        search_term="access"
        expected='-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n
            -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n
            -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n
            -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
        
        diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.13() {
    id=$1
    description="Ensure successful filesystem mounts are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        search_term="mounts"
        expected='-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n
            -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts'
        
        diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.14() {
    id=$1
    description="Ensure file deletion events by users are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
        search_term="delete"
        expected='-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n
            -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
        
        diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
   ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.15() {
    id=$1
    description="Ensure changes to system administration scope (sudoers) is collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="scope"
    expected='-w /etc/sudoers -p wa -k scope\n
        -w /etc/sudoers.d -p wa -k scope'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.16() {
    id=$1
    description="Ensure system administrator actions (sudolog) are collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="actions"
    expected='-w /var/log/sudo.log -p wa -k actions'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.17() {
    id=$1
    description="Ensure kernel module loading and unloading is collected"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    search_term="time-change"
    expected='-w /sbin/insmod -p x -k modules\n
        -w /sbin/rmmod -p x -k modules\n
        -w /sbin/modprobe -p x -k modules\n
        -a always,exit arch=b64 -S init_module -S delete_module -k modules'
    
    diff <(echo -e $expected | sed 's/^\s*//') <(grep $search_term /etc/audit/audit.rules) &>/dev/null && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.1.18() {
    id=$1
    description="Ensure the audit configuration is immutable"
    level=2
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ "$(grep "^\s*[^#]" /etc/audit/audit.rules | tail -1)" == "-e 2" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.2.1.3() {
    id=$1
    description="Ensure rsyslog default file permissions configured"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(grep -c "^\$FileCreateMode 640" /etc/rsyslog.conf) -gt 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.2.1.4() {
    id=$1
    description="Ensure rsyslog is configured to send logs to a remote host"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(grep -c "^*.*[^I][^I]*@" /etc/rsyslog.conf) -gt 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.2.2.3() {
    id=$1
    description="Ensure syslog-ng default file permissions configured"
    level=1
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(grep -c "^options {.*perms(640).*};" /etc/syslog-ng/syslog-ng.conf) -gt 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.2.2.4() {
    id=$1
    description="Ensure syslog-ng is configured to send logs to a remote host"
    level=1
    scored="Not Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(grep -c "^destination logserver { tcp(.*port(514)); };" /etc/syslog-ng/syslog-ng.conf) -gt 0 ] || state=1
    [ $(grep -c "^log { source(src); destination(logserver); };" /etc/syslog-ng/syslog-ng.conf) -gt 0 ] || state=2
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.2.3() {
    id=$1
    description="Ensure rsyslog or syslog-ng is installed"
    level=1
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
        [ $(rpm -q rsyslog &>/dev/null; echo $?) -eq 0 -o $(rpm -q syslog-ng &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_4.2.4() {
    id=$1
    description="Ensure permissions on log files are configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(find /var/log -type f -perm /027 2>/dev/null | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 5 - Access, Authentication and Authorization
test_5.1.8() {
    id=$1
    description="Ensure at/cron is restricted to authorised users"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ -f /etc/at.deny ] && state=1
    [ -f /etc/cron.deny ] && state=1
    if [ -f /etc/at.allow -a -f cron.allow ]; then
        [ $(ls -l at.allow 2>/dev/null | awk '{ print $1" "$3" "$4 }' | grep -c "-rw-r--r--. root root") -eq 1 ] || state=1
        [ $(ls -l cron.allow 2>/dev/null | awk '{ print $1" "$3" "$4 }' | grep -c "-rw-r--r--. root root") -eq 1 ] || state=1
    else
        state=1
    fi
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_5.2.2() {
    id=$1
    description="Ensure SSH Protocol is set to 2"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^Protocol\s2" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.3() {
    id=$1
    description="Ensure SSH LogLevel is set to INFO"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^LogLevel\sINFO" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.4() {
    id=$1
    description="Ensure SSH X11 forwarding is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^X11Forwarding\sno" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.5() {
    id=$1
    description="Ensure SSH MaxAuthTries is set to 4 or less"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(egrep -c "^MaxAuthTries\s[0-4]$" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.6() {
    id=$1
    description="Ensure SSH IgnoreRhosts is enabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^IgnoreRhosts\syes" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.7() {
    id=$1
    description="Ensure SSH HostbasedAuthentication is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^HostbasedAuthentication\sno" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.8() {
    id=$1
    description="Ensure SSH root login is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^PermitRootLogin\sno" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.9() {
    id=$1
    description="Ensure SSH PermitEmptyPasswords is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^PermitEmptyPasswords\sno" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.10() {
    id=$1
    description="Ensure SSH PermitUserEnvironment is disabled"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^PermitUserEnvironment\sno" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.11() {
    id=$1
    description="Ensure only approved ciphers are used"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(egrep -c "^Ciphers\saes256-ctr,aes192-ctr,aes128-ctr$" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.12() {
    id=$1
    description="Ensure only approved MAC algorithms are used"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(egrep -c "^MACs\shmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128- etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com$" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.13() {
    id=$1
    description="Ensure SSH Idle Timeout Interval is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $(grep -c "^ClientAlive" /etc/ssh/sshd_config) -eq 2 ]; then
        [ $(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}') -le 300 ] || state=1
        [ $(grep "^ClientAliveCountMax" /etc/ssh/sshd_config | awk '{print $2}') -eq 0 ] || state=1
    else
        state=1
    fi
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.14() {
    id=$1
    description="Ensure SSH LoginGraceTime is set to one minute or less"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    if [ $(grep -c "^LoginGraceTime" /etc/ssh/sshd_config) -eq 2 ]; then
        [ $(grep "^LoginGraceTime" /etc/ssh/sshd_config | awk '{print $2}') -le 60 ] && result="Pass"
    else
        state=1
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.2.16() {
    id=$1
    description="Ensure SSH warning banner is configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^Banner\s/etc/issue.net$" /etc/ssh/sshd_config) -eq 1 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_5.3.1() {
    id=$1
    description="Ensure password creation requirements are configured"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    file="/etc/security/pwquality.conf"
    
    [ $(grep -c "^password requisite pam_pwquality.so try_first_pass retry=3" /etc/pam.d/password-auth) -eq 1 ] || state=1
    [ $(grep -c "^password requisite pam_pwquality.so try_first_pass retry=3" /etc/pam.d/system-auth) -eq 1 ] || state=1
    
    if [ $(grep -c "^minlen=" $file) -eq 1 ]; then
        [ $(grep "^minlen=" $file | sed 's/^.*=-//' ) -ge 14 ] || state=1
    else
        state=1
    fi
    
    for i in dcredit ucredit ocredit lcredit; do
        if [ $(grep -c "^$i=" $file) -eq 1 ]; then
            [ $(grep "^$i=" $file | sed 's/^.*=-//' ) -ge 1 ] || state=1
        else
            state=1
        fi
    done

    [ $state -eq 0 ]&& result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"

}
test_5.3.3() {
    id=$1
    description="Ensure password reuse is limited"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for file in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
        if [ $(egrep -c "^pasword\s+sufficient\s+pam_unix.so" $file) -eq 1 ]; then
            [ $(egrep -c "^pasword\s+sufficient\s+pam_unix.so" $file | sed 's/^.*=//' ) -ge 5 ] || state=1
        else
            state=1
        fi
    done
    
    [ $state -eq 0 ]&& result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.3.4() {
    id=$1
    description="Ensure password hashing algorithm is SHA-512"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(egrep -c "^pasword\s+sufficient\s+pam_unix.so sha-512" /etc/pam.d/system-auth) -eq 1 ] || state=1
    [ $(egrep -c "^pasword\s+sufficient\s+pam_unix.so sha-512" /etc/pam.d/password-auth) -eq 1 ] || state=1
    
    [ $state -eq 0 ]&& result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_5.4.1.1() {
    id=$1
    description="Ensure password expiration is 90 days or less"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    file="/etc/login.defs"
    days=90
    if [ -s $file ]; then
        if [ $(grep -c "^PASS_MAX_DAYS" $file) -eq 1 ]; then
            [ $(awk '/^PASS_MAX_DAYS/ {print $2}' $file) -le $days ] || state=1
        fi
    fi
    
    for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1); do 
        [ $(chage --list $i 2>/dev/null | awk '/Maximum/ {print $9}') -le $days ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.4.1.2() {
    id=$1
    description="Ensure minimum days between password changes is 7 or more"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    file="/etc/login.defs"
    days=7
    if [ -s $file ]; then
        if [ $(grep -c "^PASS_MAX_DAYS" $file) -eq 1 ]; then
            [ $(awk '/^PASS_MAX_DAYS/ {print $2}' $file) -ge $days ] || state=1
        fi
    fi
    
    for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1); do 
        [ $(chage --list $i 2>/dev/null | awk '/Minimum/ {print $9}') -ge $days ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.4.1.3() {
    id=$1
    description="Ensure password expiration warning days is 7 or more"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    file="/etc/login.defs"
    days=7
    if [ -s $file ]; then
        if [ $(grep -c "^PASS_WARN_AGE" $file) -eq 1 ]; then
            [ $(awk '/^PASS_WARN_AGE/ {print $2}' $file) -ge $days ] || state=1
        fi
    fi
    
    for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1); do 
        [ $(chage --list $i 2>/dev/null | awk '/warning/ {print $10}') -ge $days ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.4.1.4() {
    id=$1
    description="Ensure inactive password lock is 30 days or less"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    file="/etc/login.defs"
    days=30
    
    [ $(useradd -D | grep INACTIVE | sed 's/^.*=//') -gt 0 -a $(useradd -D | grep INACTIVE | sed 's/^.*=//') -le $days ] || state=1
    
    for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1); do 
        if [ $(chage --list $i 2>/dev/null | awk '/inactive/ {print $4}') != "never" ]; then
            [ $(chage --list $i 2>/dev/null | awk '/inactive/ {print $4}') -le $days ] || state=1
        else
            state=1
        fi
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_5.4.2() {
    id=$1
    description="Ensure system accounts are non-login"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.4.3() {
    id=$1
    description="Ensure default group for the root account is GID 0"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep "^root:" /etc/passwd | cut -f4 -d:) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_5.4.4() {
    id=$1
    description="Ensure default group for the root account is GID 0"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^umask 027" /etc/bashrc) -eq 1 ] || state=1
    [ $(grep -c "^umask 027" /etc/profile) -eq 1 ] || state=1
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_5.6() {
    id=$1
    description="Ensure access to the su command is restricted"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c "^auth required pam_wheel.so use_uid" /etc/pam.d/su) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 6 - System Maintenance

test_6.1.1() {
    id=$1
    description="Audit system file permissions"
    level=2
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(rpm -Va --nomtime --nosize --nomd5 --nolinkto | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.1.10() {
    id=$1
    description="Ensure no world writable files exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.1.11() {
    id=$1
    description="Ensure no unowned files or directories exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.1.12() {
    id=$1
    description="Ensure no ungrouped files or directories exist"
    level=1
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_6.2.1() {
    id=$1
    description="Ensure password fields are not empty"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(awk -F: '($2 == "" )' /etc/shadow | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.x-legacy_entries() {
    id=$1
    file=$2
    description="Ensure no legacy "+" entries exists in $file"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep -c '^+:' $file) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.5() {
    id=$1
    description="Ensure root is the only UID 0 account"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(awk -F: '$3 == 0' /etc/passwd | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.6() {
    id=$1
    description="Ensure root PATH integrity"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(echo $PATH | grep -c '::') -eq 0 ] && state=1
    [ $(echo $PATH | grep -c ':$') -eq 0 ] && state=1
    
    if [ $state -eq 0 ]; then
        for p in $(echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'); do 
            if [ -d $p -a $p != "." ]; then
                perms=$(ls -hal $p)
                [ "$(echo $perms | cut -c6)" == '-' ] || state=1
                [ "$(echo $perms | cut -c9)" == '-' ] || state=1
                [ "$(echo $perms | awk '{print $3}')" == "root" ] || state=1
            else
                state=1
            fi
        done
    fi
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.7() {
    id=$1
    description="Ensure all users' home directories exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    awk -F: '{ print $1" "$3" "$6 }' /etc/passwd |\
        while read user uid dir; do
            [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ] && state=1
        done 
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.8() {
    id=$1
    description="Ensure users' home directories permissions are 750 or more restrictive"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in $(egrep -v '(halt|sync|shutdown|/sbin/nologin)' /etc/passwd | awk -F: '{print $6}'); do
        perms=$(ls -ld $dir | cut -f1 -d" ")

        [ $(echo $perms | cut -c6) == "-" ] || state=1
        [ $(echo $perms | cut -c8) == "-" ] || state=1
        [ $(echo $perms | cut -c9) == "-" ] || state=1
        [ $(echo $perms | cut -c10) == "-" ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.9() {
    id=$1
    description="Ensure users own their own home directories"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
        if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then 
            owner=$(stat -L -c "%U" "$dir")
            [ "$owner" == "$user" ] || state=1
        fi
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.10() {
    id=$1
    description="Ensure users' dot files are not group or world writable"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in `cat /etc/passwd | egrep -v '(sync|halt|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
        for file in $dir/.[A-Za-z0-9]*; do
            if [ ! -h "$file" -a -f "$file" ]; then
                fileperm=`ls -ld $file | cut -f1 -d" "`
                
                [ `echo $fileperm | cut -c6` == "-" ] || state=1
                [ `echo $fileperm | cut -c9`  == "-" ] || state=1
            fi
        done
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.11() {
    id=$1
    description="Ensure no users have .forward files"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in $(awk -F: '{ print $6 }' /etc/passwd); do
        [ -e "$dir/.forward" ] && state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.12() {
    id=$1
    description="Ensure no users have .netrc files"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in $(awk -F: '{ print $6 }' /etc/passwd); do
        [ -e "$dir/.netrc" ] && state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.13() {
    id=$1
    description="Ensure no users have .netrc files"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in $(egrep -v '(root|sync|halt|shutdown|/sbin/nologin)' /etc/passwd | awk -F: '{print $6}'); do
        file=$dir/.netrc
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`ls -ld $file | cut -f1 -d" "`
            [ `echo $fileperm | cut -c5`  != "-" ] || state=1
            [ `echo $fileperm | cut -c6`  != "-" ] || state=1
            [ `echo $fileperm | cut -c7`  != "-" ] || state=1
            [ `echo $fileperm | cut -c8`  != "-" ] || state=1
            [ `echo $fileperm | cut -c9`  != "-" ] || state=1
            [ `echo $fileperm | cut -c10`  != "-" ] || state=1
        fi
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.14() {
    id=$1
    description="Ensure no users have .rhosts files"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for dir in $(awk -F: '{ print $6 }' /etc/passwd); do
        [ -e "$dir/.rhosts" ] && state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.15() {
    id=$1
    description="Ensure all groups in /etc/passwd exist in /etc/group"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        [ $? -eq 0 ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.16() {
    id=$1
    description="Ensure no duplicate UIDs exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(cut -f3 -d: /etc/passwd | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.17() {
    id=$1
    description="Ensure no duplicate GIDs exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(cut -f3 -d: /etc/group | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.18() {
    id=$1
    description="Ensure no duplicate user names exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(cut -f1 -d: /etc/passwd | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_6.2.19() {
    id=$1
    description="Ensure no duplicate group names exist"
    level=1
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(cut -f1 -d: /etc/group | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

### Main ###
## Main script execution starts here

## Parse arguments passed in to the script
parse_args $@

## Run setup function
setup
progress & 

## Run Tests
## These tests could've been condensed using loops but I left it exploded for
## ease of understanding / updating in the future.

## Section 1 - Initial Setup
if [ $(is_test_included 1; echo $?) -eq 0 ]; then   write_cache "1,Initial Setup"
    
    ## Section 1.1 - Filesystem Configuration
    if [ $(is_test_included 1.1; echo $?) -eq 0 ]; then   write_cache "1.1,Filesystem Configuration"
        
        ## Section 1.1.1 - Disable unused filesystems
        if [ $(is_test_included 1.1.1; echo $?) -eq 0 ]; then   write_cache "1.1.1,Disable unused filesystems"
            run_test 1.1.1.1 test_1.1.1.x cramfs   ## Ensure mounting of cramfs is disabled
            run_test 1.1.1.2 test_1.1.1.x freevxfs    ## Ensure mounting of freevxfs is disabled
            run_test 1.1.1.3 test_1.1.1.x jffs2   ## Ensure mounting of jffs2 is disabled
            run_test 1.1.1.4 test_1.1.1.x hfs   ## Ensure mounting of hfs is disabled
            run_test 1.1.1.5 test_1.1.1.x hfsplus   ## Ensure mounting of hfsplus is disabled
            run_test 1.1.1.6 test_1.1.1.x squashfs   ## Ensure mounting of squashfs is disabled
            run_test 1.1.1.7 test_1.1.1.x udf   ## Ensure mounting of udf is disabled
            run_test 1.1.1.8 test_1.1.1.x vfat   ## Ensure mounting of vfat is disabled
        fi
        run_test 1.1.2 test_1.1.x-check_partition /tmp   ## 1.1.2 Ensure separate partition exists for /tmp
        run_test 1.1.3 test_1.1.x-check_fs_opts /tmp nodev   ## 1.1.3 Ensure nodev option set on /tmp
        run_test 1.1.4 test_1.1.x-check_fs_opts /tmp nosuid   ## 1.1.4 Ensure nosuid option set on /tmp
        run_test 1.1.5 test_1.1.x-check_fs_opts /tmp noexec   ## 1.1.5 Ensure noexec option set on /tmp
        run_test 1.1.6 test_1.1.x-check_partition /var   ## 1.1.6 Ensure separate partition exists for /var
        run_test 1.1.7 test_1.1.x-check_partition /var/tmp   ## 1.1.7 Ensure separate partition exists for /var/tmp
        run_test 1.1.8 test_1.1.x-check_fs_opts /var/tmp nodev   ## 1.1.8 Ensure nodev option set on /var/tmp
        run_test 1.1.9 test_1.1.x-check_fs_opts /var/tmp nosuid   ## 1.1.9 Ensure nosuid option set on /var/tmp
        run_test 1.1.10 test_1.1.x-check_fs_opts /var/tmp noexec   ## 1.1.10 Ensure noexec option set on /var/tmp
        run_test 1.1.11 test_1.1.x-check_partition /var/log   ## 1.1.11 Ensure separate partition exists for /var/log
        run_test 1.1.12 test_1.1.x-check_partition /var/log/audit   ## 1.1.12 Ensure separate partition exists for /var/log/audit
        run_test 1.1.13 test_1.1.x-check_partition /home   ## 1.1.13 Ensure separate partition exists for /home
        run_test 1.1.14 test_1.1.x-check_fs_opts /home nodev   ## 1.1.14 Ensure nodev option set on /home
        run_test 1.1.15 test_1.1.x-check_fs_opts /dev/shm nodev   ## 1.1.15 Ensure nodev option set on /dev/shm
        run_test 1.1.16 test_1.1.x-check_fs_opts /dev/shm nosuid   ## 1.1.16 Ensure nosuid option set on /dev/shm
        run_test 1.1.17 test_1.1.x-check_fs_opts /dev/shm noexec   ## 1.1.17 Ensure noexec option set on /dev/shm
        run_test 1.1.18 test_1.1.x-check_removable nodev  ## 1.1.18 Ensure nodev option set on removable media partitions
        run_test 1.1.19 test_1.1.x-check_removable nosuid  ## 1.1.19 Ensure nosuid option set on removable media partitions
        run_test 1.1.20 test_1.1.x-check_removable noexec  ## 1.1.20 Ensure noexec option set on removable media partitions
        run_test 1.1.21 test_1.1.21   ## 1.1.21 Ensure Sticky bit is set on all world-writable dirs
        run_test 1.1.22 test_1.1.22   ## 1.1.22 Disable Automounting
    fi
    
    ## Section 1.2 - Configure Software Updates
    if [ $(is_test_included 1.2; echo $?) -eq 0 ]; then   write_cache "1.2,Configure Software Updates"
        run_test 1.2.1 test_1.2.1   ## 1.2.1 Ensure package manager repositories are configured
        run_test 1.2.2 test_1.2.2   ## 1.2.2 Ensure GPG keys are configured
        run_test 1.2.3 test_1.2.3   ## 1.2.3 Ensure gpgcheck is globally activated    
    fi
    
    ## Section 1.3 - Filesystem Integrity Checking
    if [ $(is_test_included 1.3; echo $?) -eq 0 ]; then   write_cache "1.3,Filesystem Integrity Checking"
        run_test 1.3.1 test_is_installed aide AIDE   ## 1.3.1 Ensure AIDE is installed
        run_test 1.3.2 test_1.3.2   ## 1.3.2 Ensure filesystem integrity is regularly checked
    fi
    
    ## Section 1.4 - Secure Boot Settings
    if [ $(is_test_included 1.4; echo $?) -eq 0 ]; then   write_cache "1.4,Secure Boot Settings"
        run_test 1.4.1 test_perms 600 /boot/grub2/grub.cfg   ## 1.4.1 Ensure permissions on bootloader config are configured
        run_test 1.4.2 test_1.4.2   ## 1.4.2 Ensure bootloader password is set
        run_test 1.4.3 test_1.4.3   ## 1.4.3 Ensure authentication requires for single user mode
    
    fi
    
    ## Section 1.5 - Additional Process Hardening
    if [ $(is_test_included 1.5; echo $?) -eq 0 ]; then   write_cache "1.5,Additional Process Hardening"
        run_test 1.5.1 test_1.5.1   ## 1.5.1 Ensure core dumps are restricted
        run_test 1.5.2 test_1.5.2   ## 1.5.2 Ensure XD/NX support is enabled
        run_test 1.5.3 test_1.5.3   ## 1.5.3 Ensure address space layout randomisation (ASLR) is enabled
        run_test 1.5.4 test_1.5.4   ## 1.5.4 Ensure prelink is disabled
    
    fi
    
    ## Section 1.6 - Mandatory Access Control
    if [ $(is_test_included 1.6; echo $?) -eq 0 ]; then   write_cache "1.6,Mandatory Access Control"
        if [ $(is_test_included 1.6.1; echo $?) -eq 0 ]; then   write_cache "1.6.1,Configure SELinux"
            run_test 1.6.1.1 test_1.6.1.1   ## 1.6.1.1 Ensure SELinux is not disabled in bootloader configuration
            run_test 1.6.1.2 test_1.6.1.2   ## 1.6.1.2 Ensure the SELinux state is enforcing
            run_test 1.6.1.3 test_1.6.1.3   ## 1.6.1.3 Ensure SELinux policy is configured
            run_test 1.6.1.4 test_1.6.1.4   ## 1.6.1.4 Ensure SETroubleshoot is not installed
            run_test 1.6.1.5 test_1.6.1.5   ## 1.6.1.5 Ensure MCS Translation Service (mcstrans) is not installed
            run_test 1.6.1.6 test_1.6.1.6   ## 1.6.1.5 Ensure no unconfined daemons exist
        fi
        run_test 1.6.2 test_is_installed libselinux SELinux   ## 1.6.2 Ensure SELinux is installed
    fi
    
    ## Section 1.7 - Warning Banners
    if [ $(is_test_included 1.7; echo $?) -eq 0 ]; then   write_cache "1.7,Warning Banners"
        if [ $(is_test_included 1.7.1; echo $?) -eq 0 ]; then   write_cache "1.7.1,Command Line Warning Banners"
            run_test 1.7.1.1 test_1.7.1.1   ## 1.7.1.1 Ensure message of the day is configured properly (Scored)
            run_test 1.7.1.2 test_1.7.1.2   ## 1.7.1.2 Ensure local login warning banner is configured properly (Not Scored)
            run_test 1.7.1.3 test_1.7.1.3   ## 1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored)
            run_test 1.7.1.4 test_1.7.1.4   ## 1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored)
            run_test 1.7.1.5 test_perms 644 /etc/issue   ## 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
            run_test 1.7.1.6 test_perms 644 /etc/issue.net   ## 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored)
        fi
        run_test 1.7.2 test_1.7.2   ## 1.7.2 Ensure GDM login banner is configured (Scored)
    fi
    
    run_test 1.8 test_1.8   ## 1.8 Ensure updates, patches, and additional security software are installed (Not Scored) 
fi 

## Section 2 - Services
if [ $(is_test_included 2; echo $?) -eq 0 ]; then   write_cache "2,Services"
    if [ $(is_test_included 2.1; echo $?) -eq 0 ]; then   write_cache "2.1,inetd Services"
        run_test 2.1.1 test_2.1.x chargen   ## Ensure chargen services are not enabled (Scored)
        run_test 2.1.2 test_2.1.x daytime   ## Ensure daytime services are not enabled (Scored)
        run_test 2.1.3 test_2.1.x discord   ## Ensure discord services are not enabled (Scored)
        run_test 2.1.4 test_2.1.x echo   ## Ensure echo services are not enabled (Scored)
        run_test 2.1.5 test_2.1.x time   ## Ensure time services are not enabled (Scored)
        run_test 2.1.6 test_2.1.6   ## Ensure tftp is not enabled (Scored)
        run_test 2.1.7 test_2.1.7   ## Ensure xinetd is not enabled (Scored)
    fi 
    if [ $(is_test_included 2.2; echo $?) -eq 0 ]; then   write_cache "2.2,Special Purpose Services"
        if [ $(is_test_included 2.2.1; echo $?) -eq 0 ]; then   write_cache "2.2.1,Time Synchronisation"
            run_test 2.2.1.1 test_2.2.1.1   ## 2.2.1.1 Ensure time synchronisation is in use (Not Scored)
            run_test 2.2.1.2 test_2.2.1.2   ## 2.2.1.2 Ensure ntp is configured (Scored)
            run_test 2.2.1.3 test_2.2.1.3   ## 2.2.1.3 Ensure chrony is configured (Scored)
        fi
        run_test 2.2.2 test_2.2.2   ## 2.2.2 Ensure X Window System is not installed (Scored)
        run_test 2.2.3 test_2.2.x avahi avahi-daemon.service "5353" Avahi Server   ## 2.2.4 Ensure Avahi Server is not enabled (Scored)
        run_test 2.2.4 test_2.2.x cups cups.service "631" CUPS   ## 2.2.4 Ensure CUPS is not enabled (Scored)
        run_test 2.2.5 test_2.2.x dhcp dhcpd.service "67" DHCP   ## 2.2.5 Ensure DHCP server is not enabled (Scored)
        run_test 2.2.6 test_2.2.x openldap-servers slapd.service "583|:636" LDAP   ## 2.2.6 Ensure LDAP server is not enabled (Scored)
        run_test 2.2.7 test_2.2.7   ## 2.2.7 Ensure NFS and RPC are not enabled (Scored)
        run_test 2.2.8 test_2.2.x bind named.service "53" DNS   ## 2.2.8 Ensure LDAP server is not enabled (Scored)
        run_test 2.2.9 test_2.2.x vsftpd vsftpd.service "21" FTP   ## 2.2.9 Ensure FTP server is not enabled (Scored)
        run_test 2.2.10 test_2.2.x httpd httpd.service "80|:443" HTTP   ## 2.2.10 Ensure HTTP server is not enabled (Scored)
        run_test 2.2.11 test_2.2.x dovecot dovecot.service "110|:143|:587|:993|:995" IMAP and POP   ## 2.2.11 Ensure IMAP and POP server is not enabled (Scored)
        run_test 2.2.12 test_2.2.x samba smb.service "445" Samba   ## 2.2.12 Ensure Samba server is not enabled (Scored)
        run_test 2.2.13 test_2.2.x squid squid.service "3128|:80|:443" HTTP Proxy   ## 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
        run_test 2.2.14 test_2.2.x net-snmp snmpd.service "161" SNMP   ## 2.2.14 Ensure SNMP Server is not enabled (Scored)
        run_test 2.2.15 test_2.2.15   ## Ensure mail transfer agent is configured for local-only mode (Scored)
        run_test 2.2.16 test_2.2.x ypserv ypserv.service "789" NIS   ## Ensure NIS Server is not enabled (Scored)
        run_test 2.2.17 test_2.2.17   ## Ensure rsh server is not enabled (Scored)
        run_test 2.2.18 test_2.2.x telnet-server telnet.socket "23" telnet   ## Ensure telnet server is not enabled (Scored)
        run_test 2.2.19 test_2.2.x tftp-server tftp.socket "69" tfp   ## Ensure tftp server is not enabled (Scored)
        run_test 2.2.20 test_2.2.x rsync rsyncd.service "873" rsync   ## Ensure rsync service is not enabled (Scored)
        run_test 2.2.21 test_2.2.x talk-server ntalk.service "517" talk   ## Ensure talk server is not enabled (Scored)
    fi
    if [ $(is_test_included 2.3; echo $?) -eq 0 ]; then   write_cache "2.3,Service Clients"
        run_test 2.3.1 test_2.3.x ypbind NIS   ### 2.3.1 Ensure NIS Client is not installed (Scored)
        run_test 2.3.2 test_2.3.x rsh rsh   ### 2.3.2 Ensure rsh client is not installed (Scored)
        run_test 2.3.3 test_2.3.x talk talk   ## 2.3.3 Ensure talk client is not installed (Scored)
        run_test 2.3.4 test_2.3.x telnet telnet   ## 2.3.4 Ensure telnet client is not installed (Scored)
        run_test 2.3.5 test_2.3.x openldap-clients LDAP   ## 2.3.5 Ensure LDAP client is not installed (Scored)
    fi
fi

## Section 3 - Network Configuration 
if [ $(is_test_included 3; echo $?) -eq 0 ]; then   write_cache "3,Network Configuration"
    if [ $(is_test_included 3.1; echo $?) -eq 0 ]; then   write_cache "3.1,Network Parameters (Host Only)"
        run_test 3.1.1 test_3.x-single ipv4 ip_forward 0 "Ensure IP forwarding is disabled"   ## 3.1.1 Ensure IP forwarding is disabled (Scored)
        run_test 3.1.2 test_3.x-double ipv4 send_redirects 0 "Ensure packet redirect sending is not allowed"   ## 3.1.2 Ensure packet redirect sending is disabled (Scored)
    fi
    if [ $(is_test_included 3.2; echo $?) -eq 0 ]; then   write_cache "3.2,Network Parameters (Host and Router)"
        run_test 3.2.1 test_3.x-double ipv4 accept_source_route 0 "Ensure source routed packets are not accepted"   ## 3.2.1 Ensure source routed packets are not accepted (Scored)
        run_test 3.2.2 test_3.x-double ipv4 accept_redirects 0 "Ensure ICMP redirects are not accepted"   ## 3.2.2 Ensure ICMP redirects are not accepted (Scored)
        run_test 3.2.3 test_3.x-double ipv4 secure_redirects 0 "Ensure secure ICMP redirects are not accepted"   ## 3.2.3 Ensure secure ICMP redirects are not accepted (Scored)
        run_test 3.2.4 test_3.x-double ipv4 log_martians 1 "Ensure suspicious packages are logged"   ## 3.2.4 Ensure suspicious packets are logged (Scored)
        run_test 3.2.5 test_3.x-single ipv4 icmp_echo_ignore_broadcasts 1 "Ensure broadcast ICMP requests are ignored"   ## 3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
        run_test 3.2.6 test_3.x-single ipv4 icmp_ignore_bogus_error_responses 1 "Ensure bogus ICMP responses are ignored"   ## 3.2.6 Ensure bogus ICMP responses are ignored (Scored)
        run_test 3.2.7 test_3.x-double ipv4 rp_filter 1 "Ensure Reverse Path Filtering is enabled"   ## 3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
        run_test 3.2.8 test_3.x-single ipv4 tcp_syncookies 1 "Ensure TCP SYN Cookies are enabled"   ## 3.2.8 Ensure TCP SYN Cookies are enabled (Scored)
    fi
    if [ $(is_test_included 3.3; echo $?) -eq 0 ]; then   write_cache "3.3,IPv6"
        run_test 3.3.1 test_3.x-double ipv6 accept_ra 0 "Ensure IPv6 router advertisements are not accepted"   ## 3.3.1 Ensure IPv6 router advertisements are not accepted (Scored)
        run_test 3.3.2 test_3.x-double ipv6 accept_redirects 0 "Ensure IPv6 redirects are not accepted"   ## 3.3.2 Ensure IPv6 redirects are not accepted (Scored)
        run_test 3.3.3 test_3.3.3   ### Ensure IPv6 is disabled (Not Scored)
    fi
    if [ $(is_test_included 3.4; echo $?) -eq 0 ]; then   write_cache "3.4,TCP Wrappers"
        run_test 3.4.1 test_3.4.1   ## 3.4.1 Ensure TCP Wrappers is installed (Scored)
        run_test 3.4.2 test_3.4.2   ## 3.4.2 Ensure /etc/hosts.allow is configured (Scored)
        run_test 3.4.3 test_3.4.3   ## 3.4.3 Ensure /etc/hosts.deny is configured (Scored)
        run_test 3.4.4 test_3.4.x /etc/hosts.allow   ## 3.4.4 Ensure permissions on /etc/hosts.allow is configured (Scored)
        run_test 3.4.5 test_3.4.x /etc/hosts.deny   ## 3.4.5 Ensure permissions on /etc/hosts.deny are 644 (Scored)
    fi
    if [ $(is_test_included 3.5; echo $?) -eq 0 ]; then   write_cache "3.5,Uncommon Network Protocols"
        run_test 3.5.1 test_3.5.x dccp DCCP   ### 3.5.1 Ensure DCCP is disabled (Not Scored)
        run_test 3.5.2 test_3.5.x sctp SCTP   ### 3.5.2 Ensure SCTP is disabled (Not Scored)
        run_test 3.5.3 test_3.5.x rds RDS   ### 3.5.3 Ensure RDS is disabled (Not Scored)
        run_test 3.5.4 test_3.5.x tipc TIPC   ### 3.5.4 Ensure DCCP is disabled (Not Scored)
    fi
    if [ $(is_test_included 3.6; echo $?) -eq 0 ]; then   write_cache "3.6,Firewall Configuration"
        run_test 3.6.1 test_is_installed iptables IPTables   ## 3.6.1 Ensure iptables is installed (Scored)
        run_test 3.6.2 test_3.6.2   ## 3.6.2 Ensure default deny firewall policy (Scored)
        run_test 3.6.3 test_3.6.3   ## 3.6.3 Ensure loopback traffic is configured (Scored)
        run_test 3.6.4 test_3.6.4   ## 3.6.4 Ensure outbound and established connections are configured (Not Scored)
        run_test 3.6.5 skip_test "Ensure firewall rules exist for all open ports"   ## 3.6.5 Ensure firewall rules exist for all open ports (Scored)
    fi
    ## This test deviates from the benchmark's audit steps. The assumption here is that if you are on a server
    ## then you shouldn't have the wireless-tools installed for you to even use wireless interfaces
    run_test 3.7 test_is_installed wireless-tools "wireless interfaces"   ## 3.7 Ensure wireless interfacs are disabled (Not Scored)
fi

## Section 4 - Logging and Auditing
if [ $(is_test_included 4; echo $?) -eq 0 ]; then   write_cache "4,Logging and Auditing"
    if [ $(is_test_included 4.1; echo $?) -eq 0 ]; then   write_cache "4.1,Configure System Accounting"
        if [ $(is_test_included 4.1.1; echo $?) -eq 0 ]; then   write_cache "4.1.1,Configure Data Retention"
            run_test 4.1.1.1 test_4.1.1.1   ## 4.1.1.1 Ensure audtit log storage size is configured (Not Scored)
            run_test 4.1.1.2 test_4.1.1.2   ## 4.1.1.2 Ensure system is disabled when audit logs are full (Scored)
            run_test 4.1.1.3 test_4.1.1.3   ## 4.1.1.3 Ensure audit logs are not automatically deleted (Scored)
        fi
        run_test 4.1.2 test_is_enabled auditd.service auditd   ## 4.1.2 Ensue auditd service is enabled (Scored)
        run_test 4.1.3 test_4.1.3   ## 4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)
        run_test 4.1.4 test_4.1.4   ## 4.1.4 Ensure events that modify date and time information are collected (Scored)
        run_test 4.1.5 test_4.1.5   ## 4.1.5 Ensure events that modify user/group information are collected (Scored)
        run_test 4.1.6 test_4.1.6   ## 4.1.6 Ensure events that modify the system's network environment are collected (Scored)
        run_test 4.1.7 test_4.1.7   ## 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
        run_test 4.1.8 test_4.1.8   ## 4.1.8 Ensure login and logout events are collected (Scored)
        run_test 4.1.9 test_4.1.9   ## 4.1.9 Ensure session initiation information is collected (Scored)
        run_test 4.1.10 test_4.1.10   ## 4.1.10 Ensure discretionary access control permission modification events are collected (Scored)
        run_test 4.1.11 test_4.1.11   ## 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
        run_test 4.1.12 skip_test "Ensure use of privileged commands is collected"   ## 4.1.12 Ensure use of privileged commands is collected (Scored)
        run_test 4.1.13 test_4.1.13   ## 4.1.13 Ensure successful file system mounts are collected (Scored)
        run_test 4.1.14 test_4.1.14   ## 4.1.14 Ensure file deletion events by users are collected (Scored)
        run_test 4.1.15 test_4.1.15   ## 4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)
        run_test 4.1.16 test_4.1.16   ## 4.1.16 Ensure system administrator actions (sudolog) are collecteed (Scored)
        run_test 4.1.17 test_4.1.17   ## 4.1.17 Ensure kernel module loading and unloading is collected (Scored)
        run_test 4.1.18 test_4.1.18   ## 4.1.18 Ensure the audit configuration is immutable (Scored)
        
    fi
    if [ $(is_test_included 4.2; echo $?) -eq 0 ]; then   write_cache "4.2,Configure Logging"
        if [ $(is_test_included 4.2.1; echo $?) -eq 0 ]; then
            if [ $(rpm -q rsyslog &>/dev/null; echo $?) -eq 0 ]; then   write_cache "4.2.1,Configure rsyslog"
                run_test 4.2.1.1 test_is_enabled rsyslog.service rsyslog   ## 4.2.1.1 Ensure rsyslog service is enabled (Scored)
                run_test 4.2.1.2 skip_test "Ensure logging is configured"   ## 4.2.1.2 Ensure logging is configured (Scored)
                run_test 4.2.1.3 test_4.2.1.3   ## 4.2.1.3 Ensure rsyslog default file permissions configured (Scored)
                run_test 4.2.1.4 test_4.2.1.4   ## 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)
                run_test 4.2.1.5 skip_test "Ensure remote rsyslog messages are only accepted on designated log hosts"   ## 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts (Not Scored)
            else
                write_cache "4.2.1,Configure rsyslog,Skipped"
            fi
        fi
        if [ $(is_test_included 4.2.2; echo $?) -eq 0 ]; then
            if [ $(rpm -q syslog-ng &>/dev/null; echo $?) -eq 0 ]; then   write_cache "4.2.2,Configure syslog-ng"
                run_test 4.2.1.1 test_is_enabled syslog-ng.service syslog-ng   ## 4.2.2.1 Ensure syslog-ng service is enabled (Scored)
                run_test 4.2.2.2 skip_test "Ensure logging is configured"   ## 4.2.2.2 Ensure logging is configured (Scored)
                run_test 4.2.2.3 test_4.2.2.3   ## 4.2.1.3 Ensure syslog-ng default file permissions configured (Scored)
                run_test 4.2.2.4 test_4.2.2.4   ## 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Scored)
                run_test 4.2.2.5 skip_test "Ensure remote syslog-ng messages are only accepted on designated log hosts"   ## 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts (Not Scored)
            else
                write_cache "4.2.2,Configure syslog-ng,Skipped"
            fi
        fi
        run_test 4.2.3 test_4.2.3   ## 4.2.3 Ensure rsyslog or syslog-ng is installed (Scored)
        run_test 4.2.4 test_4.2.4   ## 4.2.4 Ensure permissions on all logfiles are configured (Scored)
    fi
    run_test 4.3 skip_test "Ensure logrotate is configured"   ## 4.3 Ensure logrotate is configured (Not Scored)
fi

## Section 5 - Access, Authentication and Authorization
if [ $(is_test_included 5; echo $?) -eq 0 ]; then   write_cache "5,Access Authentication and Authorization"
    if [ $(is_test_included 5.1; echo $?) -eq 0 ]; then   write_cache "5.1,Configure cron"
        run_test 5.1.1 test_is_enabled crond "cron daemon"   ## 5.1.1 Ensure cron daemon is enabled (Scored)
        run_test 5.1.2 test_perms 600 /etc/crontab   ## 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
        run_test 5.1.3 test_perms 600 /etc/cron.hourly   ## 5.1.2 Ensure permissions on /etc/cron.hourly are configured (Scored)
        run_test 5.1.4 test_perms 600 /etc/cron.daily   ## 5.1.2 Ensure permissions on /etc/cron.daily are configured (Scored)
        run_test 5.1.5 test_perms 600 /etc/cron.weekly   ## 5.1.2 Ensure permissions on /etc/cron.weekly are configured (Scored)
        run_test 5.1.6 test_perms 600 /etc/cron.monthly   ## 5.1.2 Ensure permissions on /etc/cron.monthly are configured (Scored)
        run_test 5.1.7 test_perms 600 /etc/cron.d   ## 5.1.2 Ensure permissions on /etc/cron.d are configured (Scored)
        run_test 5.1.8 test_5.1.8   ## Ensure at/cron is restri9cted to authorized users (Scored)
    fi
    if [ $(is_test_included 5.2; echo $?) -eq 0 ]; then   write_cache "5.2,SSH Server Configuration"
        run_test 5.2.2 test_perms 600 /etc/ssh/sshd_config   ## 5.6.2 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
        run_test 5.2.3 test_5.2.3   ## Ensure SSH Protocol is set to 2 (Scored)
        run_test 5.2.4 test_5.2.4   ## Ensure SSH LogLevel is set to INFO (Scored)
        run_test 5.2.5 test_5.2.5   ## Ensure SSH X11 forwarding is disabled (Scored)
        run_test 5.2.6 test_5.2.6   ## 5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored)
        run_test 5.2.7 test_5.2.7   ## 5.2.7 Ensure SSH HostbasedAUthentication is disabled (Scored)
        run_test 5.2.8 test_5.2.8   ## 5.2.8 Ensure root login is disabled (Scored)
        run_test 5.2.9 test_5.2.9   ## 5.2.9 Ensure PermitEmptyPasswords is disabled (Scored)
        run_test 5.2.10 test_5.2.10   ## 5.2.10 Ensure PermitUserEnvironment is disabled (Scored)
        run_test 5.2.11 test_5.2.11   ## 5.2.11 Ensure only approved ciphers are used (Scored)
        run_test 5.2.12 test_5.2.12   ## 5.2.12 Ensure only approved MAC algorithms are used (Scored)
        run_test 5.2.13 test_5.2.13   ## 5.2.13 Ensure SSH Idle Timeout Interval is configured (Scored)
        run_test 5.2.14 test_5.2.14   ## 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
        run_test 5.2.15 skip_test "Ensure SSH access is limited"   ## 5.2.15 Ensure (Scored)
        run_test 5.2.16 test_5.2.16   ## 5.2.16 Ensure SSH warning banner is configured (Scored)
    fi
    if [ $(is_test_included 5.3; echo $?) -eq 0 ]; then   write_cache "5.3,Configure PAM"
        run_test 5.3.1 test_5.3.1   ## 5.3.1 Ensure password creation requirements are configured (Scored)
        run_test 5.3.2 skip_test "Ensure lockout for failed password attempts is configured"   ## 5.3.2 Ensure lockout for failed password attempts is configured (Scored)
        run_test 5.3.3 test_5.3.3   ## 5.3.3 Ensure password reuse is limited (Scored)
        run_test 5.3.4 test_5.3.4   ## 5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)
    fi
    if [ $(is_test_included 5.4; echo $?) -eq 0 ]; then   write_cache "5.4,User Accounts and Environment"
        if [ $(is_test_included 5.4.1; echo $?) -eq 0 ]; then   write_cache "5.4.1,Set Shadow Password Suite Passwords"
            run_test 5.4.1.1 test_5.4.1.1   ## 5.4.1.1 Ensure password expiration is 90 days or less (Scored)
            run_test 5.4.1.2 test_5.4.1.2   ## 5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)
            run_test 5.4.1.3 test_5.4.1.3   ## 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
            run_test 5.4.1.4 test_5.4.1.4   ## 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
        fi
        run_test 5.4.2 test_5.4.2   ## 5.4.2 Ensure system accounts are non-login (Scored)
        run_test 5.4.3 test_5.4.3   ## 5.4.2 Ensure default group for the root account is GID 0 (Scored)
        run_test 5.4.4 test_5.4.4   ## 5.4.3 Ensure default user umask is 027 or more restrictive (Scored)
    fi
    run_test 5.5 skip_test "Ensure root login is restricted to system console"   ## 5.5 Ensure root login is restricted to system console (Not Scored)
    run_test 5.6 test_5.6   ## 5.6 Ensure access to the su command is restricted (Scored)
fi

## Section 6 - System Maintenance 
if [ $(is_test_included 6; echo $?) -eq 0 ]; then   write_cache "6,System Maintenance"
    if [ $(is_test_included 6.1; echo $?) -eq 0 ]; then   write_cache "6.1,System File Permissions"
        run_test 6.1.1 test_6.1.1   ## 6.1.1 Audit system file permissions (Not Scored)
        run_test 6.1.2 test_perms 644 /etc/passwd   ## 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
        run_test 6.1.3 test_perms 000 /etc/shadow   ## 6.1.3 Ensure permissions on /etc/shadow are configured (Scored)
        run_test 6.1.4 test_perms 644 /etc/group   ## 6.1.4 Ensure permissions on /etc/group are configured (Scored)
        run_test 6.1.5 test_perms 600 /etc/gshadow   ## 6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)
        run_test 6.1.6 test_perms 600 /etc/passwd-   ## 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
        run_test 6.1.7 test_perms 600 /etc/shadow-   ## 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
        run_test 6.1.8 test_perms 600 /etc/group-   ## 6.1.8 Ensure permissions on /etc/group- are configured (Scored)
        run_test 6.1.9 test_perms 600 /etc/gshadow-   ## 6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored)
        run_test 6.1.10 test_6.1.10   ## Ensure no world-writable files exist (Scored)
        run_test 6.1.11 test_6.1.11   ## Ensure no unowned files or directories exist (Scored)
        run_test 6.1.12 test_6.1.12   ## Ensure no ungrouped files or directories exist (Scored)
        run_test 6.1.13 skip_test "Audit SUID executables"   ## 6.1.13 Audit SUID executables (Not Scored)
        run_test 6.1.14 skip_test "Audit SGID executables"   ## 6.1.14 Audit SGID executables (Not Scored)
    fi
    if [ $(is_test_included 6.2; echo $?) -eq 0 ]; then   write_cache "6.2,User and Group Settings"
        run_test 6.2.1 test_6.2.1   ## 6.2.1 Ensure password fields are not empty (Scored)
        run_test 6.2.2 test_6.2.x-legacy_entries /etc/passwd   ## 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
        run_test 6.2.3 test_6.2.x-legacy_entries /etc/shadow   ## 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
        run_test 6.2.4 test_6.2.x-legacy_entries /etc/group   ## 6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored)
        run_test 6.2.5 test_6.2.5   ## 6.2.5 Ensure root is the only GID 0 account (Scored)
        run_test 6.2.6 test_6.2.6   ## 6.2.6 Ensure root PATH integrity (Scored)
        run_test 6.2.7 test_6.2.7   ## 6.2.7 Ensure all users' home directories exist (Scored)
        run_test 6.2.8 test_6.2.8   ## 6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)
        run_test 6.2.9 test_6.2.9   ## 6.2.9 Ensure users own their own home directories (Scored)
        run_test 6.2.10 test_6.2.10   ## 6.2.10 Ensure users' dot files are not group or world writiable (Scored)
        run_test 6.2.11 test_6.2.11   ## 6.2.11 Ensure no users have .forward files (Scored)
        run_test 6.2.12 test_6.2.12   ## 6.2.12 Ensure no users have .netrc files (Scored)
        run_test 6.2.13 test_6.2.13   ## 6.2.13 Ensure users' .netrc files are not group or world accessible
        run_test 6.2.14 test_6.2.14   ## 6.2.14 Ensure no users have .rhosts files (Scored)
        run_test 6.2.15 test_6.2.15   ## 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
        run_test 6.2.16 test_6.2.16   ## 6.2.16 Ensure no duplicate UIDs exist (Scored)
        run_test 6.2.17 test_6.2.17   ## 6.2.17 Ensure no duplicate GIDs exist (Scored)
        run_test 6.2.18 test_6.2.18   ## 6.2.18 Ensure no duplicate user names exist (Scored)
        run_test 6.2.19 test_6.2.19   ## 6.2.19 Ensure no duplicate group names exist (Scored) 
    fi
fi


## Wait while all tests exit
wait
[ $debug == "True" ] && write_debug "All tests have completed"

## Output test results
outputter
tidy_up

[ $debug == "True" ] && write_debug "Exiting with code $exit_code"
exit $exit_code
