#!/usr/bin/env python3

from os import path

import pytest

import cis_audit

test = cis_audit.CISAudit()


def test_parse_arg_debug(caplog):
    """Test that the '--debug' argument turns on debug logging"""
    args = [path.relpath(__file__), '--debug']
    cis_audit._parse_arguments(argv=args)

    assert caplog.records[0].msg == 'Debugging enabled'


def test_parse_arg_log_level_debug(caplog):
    """Test that the '--log-level DEBUG' argument turns on debug logging"""
    args = [path.relpath(__file__), '--log-level', 'DEBUG']
    cis_audit._parse_arguments(args)

    assert caplog.records[0].msg == 'Debugging enabled'


def test_parse_arg_level_1(caplog):
    """Test that the '--level 1' argument sets args.level to 1"""
    args = [path.relpath(__file__), '--debug', '--level', '1']

    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to run Level 1 tests':
            status = True
            break

    assert status


def test_parse_arg_level_2(caplog):
    """Test that the '--level 2' argument sets args.level to 2"""
    args = [path.relpath(__file__), '--debug', '--level', '2']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to run Level 2 tests':
            status = True
            break

    assert status


def test_parse_arg_level_default(caplog):
    """Test that the default level argument sets args.level to 0"""
    args = [path.relpath(__file__), '--debug']
    cis_audit._parse_arguments(argv=args)

    status = False
    for record in caplog.records:
        if record.msg == 'Going to run tests from any level':
            status = True
            break

    assert status


def test_parse_arg_include(caplog):
    args = [path.relpath(__file__), '--debug', '--include', '1.1', '2.2.2']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Include list is populated "[\'1.1\', \'2.2.2\']"':
            status = True
            break

    assert status


def test_parse_arg_exclude(caplog):
    args = [path.relpath(__file__), '--debug', '--exclude', '1.1', '2.2.2']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Exclude list is populated "[\'1.1\', \'2.2.2\']"':
            status = True
            break

    assert status


def test_parse_arg_nice(caplog):
    args = [path.relpath(__file__), '--debug', '--nice']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Tests will run with reduced CPU priority':
            status = True
            break

    assert status


def test_parse_arg_no_nice(caplog):
    args = [path.relpath(__file__), '--debug', '--no-nice']
    cis_audit._parse_arguments(argv=args)
    status = True

    for record in caplog.records:
        if record.msg == 'Tests will run with reduced CPU priority':
            status = False
            break

    assert status


def test_parse_arg_no_color(caplog):
    args = [path.relpath(__file__), '--debug', '--no-color']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Coloured output will be disabled':
            status = True
            break

    assert status


def test_parse_arg_no_colour(caplog):
    args = [path.relpath(__file__), '--debug', '--no-colour']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Coloured output will be disabled':
            status = True
            break

    assert status


def test_parse_arg_outformat_csv(caplog):
    args = [path.relpath(__file__), '--debug', '--outformat', 'csv']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "csv" outputter':
            status = True
            break

    assert status


def test_parse_arg_outformat_json(caplog):
    args = [path.relpath(__file__), '--debug', '--outformat', 'json']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "json" outputter':
            status = True
            break

    assert status


def test_parse_arg_outformat_text(caplog):
    args = [path.relpath(__file__), '--debug', '--outformat', 'text']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "text" outputter':
            status = True
            break

    assert status


def test_parse_arg_csv(caplog):
    args = [path.relpath(__file__), '--debug', '--csv']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "csv" outputter':
            status = True
            break

    assert status


def test_parse_arg_json(caplog):
    args = [path.relpath(__file__), '--debug', '--json']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "json" outputter':
            status = True
            break

    assert status


def test_parse_arg_system_type_workstation(caplog):
    args = [path.relpath(__file__), '--debug', '--workstation']
    cis_audit._parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to use "workstation" levels for test determination':
            status = True
            break

    assert status


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
