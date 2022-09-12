#!/usr/bin/env python3

import pytest
from cis_audit import CISAudit
from datetime import datetime

test = CISAudit()


def test_get_utcnow():
    testtime = test._get_utcnow()
    realtime = datetime.utcnow()
    timediff = realtime - testtime

    assert timediff.seconds < 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
