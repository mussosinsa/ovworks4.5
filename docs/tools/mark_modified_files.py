#!/usr/bin/python3
#
# OV-Works -- modification notices in the upstream files OV-Works changed
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#

"""Puts a modification notice at the head of every upstream oVirt file that OV-Works changed.

Apache License 2.0, section 4(b): modified files carry a prominent notice that they were
changed. The files are the ones git reports as modified against the upstream release the
product is built on; files developed for OV-Works (new) are not touched.

    python3 docs/tools/mark_modified_files.py [--base REF] [--check]

Idempotent: a file that already carries the notice is left alone. --check only reports the
modified files that lack it, and exits 1 when there are any.

The notice goes where the file's own syntax allows a comment and nothing breaks: after a
shebang and a coding line, after an XML declaration, as a JSP comment in a JSP. A file whose
format has no comments (a JAR manifest) is listed and skipped.
"""

import argparse
import subprocess
import sys


DEFAULT_BASE = 'refs/upstream/ovirt-engine-4.5.6'

MARK = 'Modified by 새올정보기술'
NOTICE = (
    MARK + ' for OV-Works (2026). '
    'Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md'
)

# Formats without comments: nothing can be put in them.
UNMARKABLE = ('MANIFEST.MF',)


def comment_style(path):
    name = path.rsplit('/', 1)[-1]
    if name.endswith('.in'):
        name = name[:-3]
    if name in UNMARKABLE:
        return None
    extension = name.rsplit('.', 1)[-1] if '.' in name else name
    if extension == 'java':
        return '// {}'
    if extension == 'xml':
        return '<!-- {} -->'
    if extension == 'jsp':
        return '<%-- {} --%>'
    if extension == 'sql':
        return '-- {}'
    if extension == 'adoc':
        return '// {}'
    if extension == '8':
        return '.\\" {}'
    # Python, shell, properties, YAML, make, spec, Apache and systemd configuration, gitignore.
    return '# {}'


def insertion_index(lines, path):
    """Where the notice goes: after what has to stay first in the file."""
    index = 0
    # dbfunc-common reads the '--#source' directives of an upgrade script only from its first lines.
    while index < len(lines) and lines[index].startswith('--#source'):
        index += 1
    if index:
        return index
    if lines and lines[0].startswith('#!'):
        index = 1
        if len(lines) > 1 and 'coding' in lines[1] and lines[1].startswith('#'):
            index = 2
    elif lines and lines[0].lstrip().startswith('<?xml'):
        index = 1
    return index


def mark(path):
    style = comment_style(path)
    if style is None:
        return 'unmarkable'
    with open(path, encoding='utf-8') as stream:
        text = stream.read()
    if MARK in text:
        return 'already'
    lines = text.splitlines(keepends=True)
    newline = '\r\n' if lines and lines[0].endswith('\r\n') else '\n'
    index = insertion_index(lines, path)
    lines.insert(index, style.format(NOTICE) + newline)
    with open(path, 'w', encoding='utf-8', newline='') as stream:
        stream.write(''.join(lines))
    return 'marked'


def modified_files(base):
    output = subprocess.run(
        ('git', 'diff', '--name-only', '--no-renames', '--diff-filter=M', base, 'HEAD'),
        check=True, stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout
    return [line for line in output.splitlines() if line]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--base', default=DEFAULT_BASE)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()

    results = {'marked': [], 'already': [], 'unmarkable': []}
    for path in modified_files(args.base):
        if args.check:
            style = comment_style(path)
            with open(path, encoding='utf-8') as stream:
                present = MARK in stream.read()
            results['unmarkable' if style is None else 'already' if present else 'marked'].append(path)
        else:
            results[mark(path)].append(path)

    if args.check:
        for path in results['marked']:
            print('missing: ' + path)
        print('{} carry the notice, {} lack it, {} cannot carry one'.format(
            len(results['already']), len(results['marked']), len(results['unmarkable'])))
        return 1 if results['marked'] else 0

    for path in results['unmarkable']:
        print('skipped (no comment syntax): ' + path)
    print('{} marked, {} already marked, {} skipped'.format(
        len(results['marked']), len(results['already']), len(results['unmarkable'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
