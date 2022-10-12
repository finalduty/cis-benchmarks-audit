#!/usr/bin/env python3

from types import GeneratorType

import pytest

from cis_audit import CISAudit

test = CISAudit()


def test_integration__get_homedirs_pass():
    homedirs = test._get_homedirs()
    homedirs_list = list(homedirs)

    assert isinstance(homedirs, GeneratorType)
    assert homedirs_list[0] == ('root', 0, '/root')
    assert homedirs_list[1] == ('vagrant', 1000, '/home/vagrant')


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-W', 'ignore:Module already imported:pytest.PytestWarning'])
