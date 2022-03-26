#!/usr/bin/env bash
## Helper to make sure the audit modules are sorted alphabetically so they're easier to find

diff -y <(grep 'def audit_' cis_audit.py) <(grep 'def audit_' cis_audit.py | LC_COLLATE=C sort)
