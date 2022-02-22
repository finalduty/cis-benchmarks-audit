#!/usr/bin/env python3
## andy.dustin@gmail.com [rev: 83422a0e]

from os import path
from cis_audit import parse_arguments


def test_parse_debug(caplog):
    """Test that the '--debug' argument turns on debug logging"""
    args = [path.relpath(__file__), '--debug']
    parse_arguments(argv=args)

    assert caplog.records[0].msg == 'Debugging enabled'


def test_parse_log_level_debug(caplog):
    """Test that the '--log-level DEBUG' argument turns on debug logging"""
    args = [path.relpath(__file__), '--log-level', 'DEBUG']
    parse_arguments(args)

    assert caplog.records[0].msg == 'Debugging enabled'


def test_parse_level_1(caplog):
    """Test that the '--level 1' argument sets args.level to 1"""
    args = [path.relpath(__file__), '--debug', '--level', '1']

    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to run Level 1 tests':
            status = True
            break

    assert status


def test_parse_level_2(caplog):
    """Test that the '--level 2' argument sets args.level to 2"""
    args = [path.relpath(__file__), '--debug', '--level', '2']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Going to run Level 2 tests':
            status = True
            break

    assert status


def test_parse_level_default(caplog):
    """Test that the default level argument sets args.level to 0"""
    args = [path.relpath(__file__), '--debug']
    parse_arguments(argv=args)

    status = False
    for record in caplog.records:
        if record.msg == 'Going to run tests from any level':
            status = True
            break

    assert status


def test_parse_include(caplog):
    args = [path.relpath(__file__), '--debug', '--include', '1.1', '2.2.2']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Include list is populated "[\'1.1\', \'2.2.2\']"':
            status = True
            break

    assert status


def test_parse_exclude(caplog):
    args = [path.relpath(__file__), '--debug', '--exclude', '1.1', '2.2.2']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Exclude list is populated "[\'1.1\', \'2.2.2\']"':
            status = True
            break

    assert status


def test_parse_nice(caplog):
    args = [path.relpath(__file__), '--debug', '--nice']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Tests will run with reduced CPU priority':
            status = True
            break

    assert status


def test_parse_no_nice(caplog):
    args = [path.relpath(__file__), '--debug', '--no-nice']
    parse_arguments(argv=args)
    status = True

    for record in caplog.records:
        if record.msg == 'Tests will run with reduced CPU priority':
            status = False
            break

    assert status


def test_parse_no_color(caplog):
    args = [path.relpath(__file__), '--debug', '--no-color']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Coloured output will be disabled':
            status = True
            break

    assert status


def test_parse_no_colour(caplog):
    args = [path.relpath(__file__), '--debug', '--no-colour']
    parse_arguments(argv=args)
    status = False

    for record in caplog.records:
        if record.msg == 'Coloured output will be disabled':
            status = True
            break

    assert status
