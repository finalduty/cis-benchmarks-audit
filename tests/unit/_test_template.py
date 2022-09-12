#!/usr/bin/env python3

import cis_audit
import pytest

test = cis_audit.CISAudit()


if __name__ == '__main__':
    pytest.main([__file__])
