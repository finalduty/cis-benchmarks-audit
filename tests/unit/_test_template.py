#!/usr/bin/env python3

import pytest

import cis_audit

test = cis_audit.CISAudit()


if __name__ == '__main__':
    pytest.main([__file__])
