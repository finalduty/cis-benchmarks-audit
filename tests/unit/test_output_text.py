#!/usr/bin/env python3

import pytest

from cis_audit import CISAudit

results = [
    ('1', 'section header'),
    ('1.1', 'subsection header'),
    ('1.1.1', 'test 1.1.1', 1, 'Pass', '1ms'),
    ('2', 'section header'),
    ('2.1', 'test 2.1', 1, 'Fail', '10ms'),
    ('2.2', 'test 2.2', 2, 'Pass', '100ms'),
    ('2.3', 'test 2.3', 1, 'Not Implemented'),
]


def test_output_text(capsys):
    CISAudit().output_text(data=results)

    output, error = capsys.readouterr()
    print(output)

    assert error == ''
    assert output.split('\n')[0] == "ID     Description        Level      Result       Duration"
    assert output.split('\n')[1] == "-----  -----------------  -----  ---------------  --------"
    assert output.split('\n')[2] == ""
    assert output.split('\n')[3] == "1      section header                                     "
    assert output.split('\n')[4] == "1.1    subsection header                                  "
    assert output.split('\n')[5] == "1.1.1  test 1.1.1           1         Pass             1ms"
    assert output.split('\n')[6] == ""
    assert output.split('\n')[7] == "2      section header                                     "
    assert output.split('\n')[8] == "2.1    test 2.1             1         Fail            10ms"
    assert output.split('\n')[9] == "2.2    test 2.2             2         Pass           100ms"
    assert output.split('\n')[10] == "2.3    test 2.3             1    Not Implemented          "


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov', '-v'])
