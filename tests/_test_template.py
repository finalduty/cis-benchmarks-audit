#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch
import cis_audit
import pytest

test = cis_audit.CISAudit()


if __name__ == '__main__':
    pytest.main([__file__])
