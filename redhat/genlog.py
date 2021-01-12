#!/usr/bin/python3
#
# This script parses a git log from stdin, which should be given with:
# $ git log [<options>] -z --format="- %s (%an)%n%b" [<range>] [[--] <path>...] | ...
# And then outputs to stdout a trimmed changelog for use with rpm packaging
#
# Author: Herton R. Krzesinski <herton@redhat.com>
# Copyright (C) 2021 Red Hat, Inc.
#
# This software may be freely redistributed under the terms of the GNU
# General Public License (GPL).

"""Parses a git log from stdin, and output a log entry for an rpm."""

import re
import sys

def find_bz_in_line(line, prefix):
    """Return bug number from properly formated Bugzilla: line."""
    # BZs must begin with '{prefix}: ' and contain a complete BZ URL
    line = line.rstrip()
    pattern = prefix + r': http(s)?://bugzilla\.redhat\.com/(show_bug\.cgi\?id=)?(?P<bug>\d{4,8})$'
    bznum_re = re.compile(pattern)
    bzn = set()
    match = bznum_re.match(line)
    if match:
        bzn.add(match.group('bug'))
    return bzn


def find_cve_in_line(line):
    """Return cve number from properly formated CVE: line."""
    # CVEs must begin with 'CVE: '
    cve_set = set()
    if not line.startswith("CVE: "):
        return cve_set
    _cves = line[len("CVE: "):].split()
    pattern = "(?P<cve>CVE-[0-9]+-[0-9]+)"
    cve_re = re.compile(pattern)
    for cve_item in _cves:
        cve = cve_re.match(cve_item)
        if cve:
            cve_set.add(cve.group('cve'))
    return cve_set


def parse_commit(commit):
    """Extract metadata from a commit log message."""
    lines = commit.split('\n')

    # remove any '%' character, since it'll be used inside the rpm spec changelog
    log_entry = lines[0].replace("%","")

    cve_set = set()
    bug_set = set()
    zbug_set = set()
    for line in lines[1:]:
        # Process Bugzilla and ZStream Bugzilla entries
        bug_set.update(find_bz_in_line(line, 'Bugzilla'))
        zbug_set.update(find_bz_in_line(line, 'Z-Bugzilla'))

        # Grab CVE tags if they are present
        cve_set.update(find_cve_in_line(line))

    return (log_entry, sorted(cve_set), sorted(bug_set), sorted(zbug_set))


if __name__ == "__main__":
    commits = sys.stdin.read().split('\0')
    for c in commits:
        if not c:
            continue
        log_item, cves, bugs, zbugs = parse_commit(c)
        entry = f"{log_item}"
        if bugs or zbugs:
            entry += " ["
            if zbugs:
                entry += " ".join(zbugs)
            if bugs and zbugs:
                entry += " "
            if bugs:
                entry += " ".join(bugs)
            entry += "]"
        if cves:
            entry += " {" + " ".join(cves) + "}"
        print(entry)
