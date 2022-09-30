#!/usr/bin/python3
## https://docs.pytest.org/en/latest/reference/fixtures.html#conftest-py-sharing-fixtures-across-multiple-files

import pytest
from tests.integration import shellexec


@pytest.fixture(scope='module')
def setup_install_gdm():
    shellexec('yum install -y gdm')
    shellexec('mkdir -pv /etc/dconf/profile')
    shellexec('mkdir -pv /etc/dconf/db/gdm.d')

    yield None

    shellexec('yum remove -y gdm')
