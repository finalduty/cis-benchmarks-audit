#!/bin/bash

export PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin

yum install -y python3-pip

cd /vagrant || exit 1

python3 -m pip install --user --upgrade pip
python3 -m pip install --user pipenv
pipenv lock -r --dev > requirements.txt

if [ -f requirements.txt ]; then 
    python3 -m pip install --user -r requirements.txt
fi
