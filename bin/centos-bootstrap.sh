#!/bin/bash

cat << EOF > /root/.bash_profile
# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
        . ~/.bashrc
fi

# User specific environment and startup programs

PATH=/root/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin

export PATH
EOF

#shellcheck disable=SC1091
source /root/.bash_profile

yum install -y python3-pip

cd /vagrant || exit 1

python3 -m pip install --user --upgrade pip
python3 -m pip install --user pipenv
pipenv lock -r --dev > requirements.txt

if [ -f requirements.txt ]; then 
    python3 -m pip install --user -r requirements.txt
fi

## Preinstall updates to reduce time certain integration tests take to execute
yum update -y

## Preinstall gdm dependencies to reduce time integration tests take to execute
## I know that we could use `yum deplist` for this, but this was quicker/easier
yum install gdm -y
yum remove gdm -y
