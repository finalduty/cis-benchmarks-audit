#!/usr/bin/python3
## https://docs.pytest.org/en/latest/reference/fixtures.html#conftest-py-sharing-fixtures-across-multiple-files

import os
import shutil
import pytest
from tests.integration import shellexec


@pytest.fixture(scope='module')
def setup_install_gdm():
    shellexec('yum install -y gdm')
    shellexec('mkdir -pv /etc/dconf/profile')
    shellexec('mkdir -pv /etc/dconf/db/gdm.d')

    yield None

    shellexec('yum remove -y gdm')


@pytest.fixture(scope='session')
def setup_install_nftables():
    shellexec('yum install -y nftables')
    shellexec('nft delete table inet filter')
    shellexec('nft create table inet filter')
    shellexec(R'nft create chain inet filter input { type filter hook input priority 0 \; }')
    shellexec(R'nft create chain inet filter forward { type filter hook forward priority 0 \; }')
    shellexec(R'nft create chain inet filter output { type filter hook output priority 0 \; }')

    yield None

    # shellexec('nft delete chain inet filter')
    # shellexec('yum remove -y nftables')


@pytest.fixture
def setup_selinux_enforcing():
    ## Setup
    original_status = shellexec('getenforce').stdout[0]
    shutil.copy('/etc/selinux/config', '/etc/selinux/config.bak')

    shellexec('setenforce 1')
    shellexec("sed -i '/^SELINUX=/ s/=.*/=enforcing/' /etc/selinux/config")

    yield None

    ## Tear-down
    shellexec(f'setenforce {original_status}')
    shutil.move('/etc/selinux/config.bak', '/etc/selinux/config')


@pytest.fixture
def setup_selinux_permissive():
    ## Setup
    original_status = shellexec('getenforce').stdout[0]
    shutil.copy('/etc/selinux/config', '/etc/selinux/config.bak')

    shellexec('setenforce 0')
    shellexec("sed -i '/^SELINUX=/ s/=.*/=permissive/' /etc/selinux/config")

    yield None

    ## Tear-down
    shellexec(f'setenforce {original_status}')
    shutil.move('/etc/selinux/config.bak', '/etc/selinux/config')


@pytest.fixture
def setup_selinux_disabled():
    ## Setup
    shutil.copy('/etc/selinux/config', '/etc/selinux/config.bak')

    shellexec("sed -i '/^SELINUX=/ s/=.*/=disabled/' /etc/selinux/config")
    with open('/usr/local/sbin/sestatus', 'w') as f:
        f.write('echo SELinux status:                 disabled')
    shellexec('chmod +x /usr/local/sbin/sestatus')

    yield None

    ## Tear-down
    shutil.move('/etc/selinux/config.bak', '/etc/selinux/config')
    os.remove('/usr/local/sbin/sestatus')
