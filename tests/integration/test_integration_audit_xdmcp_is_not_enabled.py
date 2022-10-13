#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit
from tests.integration import shellexec

test = CISAudit()


@pytest.fixture
def setup_to_fail():
    ## Setup
    shellexec(R"sed -i '/\[xdmcp\]/aEnable=true' /etc/gdm/custom.conf")

    yield None

    ## Tear-down
    shellexec(R" sed -i '/^Enable=true/d' /etc/gdm/custom.conf")


def test_integration_audit_xdmcp_not_enabled_pass_gdm_installed(setup_install_gdm):
    state = test.audit_xdmcp_not_enabled()
    assert state == 0


def test_integration_audit_xdmcp_not_enabled_fail(setup_install_gdm, setup_to_fail):
    state = test.audit_xdmcp_not_enabled()
    assert state == 1


def test_integration_audit_xdmcp_not_enabled_pass_gdm_not_installed():
    state = test.audit_xdmcp_not_enabled()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
