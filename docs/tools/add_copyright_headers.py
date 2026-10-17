#!/usr/bin/python3
#
# OV-Works -- copyright headers of the files developed for OV-Works
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#

"""Puts the 새올정보기술 copyright header in every file developed for OV-Works that lacks one.

The files are the ones git reports as new against the upstream oVirt Engine release the product
is built on. A file that already names a copyright holder is left alone: one of ours, or a copy
of an upstream file, whose upstream notice stays. A file with a license line but no copyright
line gets the copyright line just above it.

    python3 docs/tools/add_copyright_headers.py [--base REF] [--check]

Documents (Markdown, which carry their own document information table), JSON and formats
without comments are not touched. Idempotent; --check only lists the files that lack a header.
"""

import argparse
import subprocess
import sys


DEFAULT_BASE = 'refs/upstream/ovirt-engine-4.5.6'

HOLDER = '새올정보기술 (OV-Works), 2026'
COPYRIGHT = 'Copyright ' + HOLDER
LICENSE = 'SPDX-License-Identifier: Apache-2.0'
HEAD_LINES = 20

SKIPPED_EXTENSIONS = ('md', 'json', 'MF')


def kind(path):
    name = path.rsplit('/', 1)[-1]
    if name.endswith('.in'):
        name = name[:-3]
    extension = name.rsplit('.', 1)[-1] if '.' in name else ''
    if extension in SKIPPED_EXTENSIONS:
        return None
    if path.startswith('docs/') and not path.startswith('docs/tools/'):
        return None
    if extension == 'java':
        return 'java'
    if extension in ('xml', 'html'):
        return 'markup'
    if extension == 'sql':
        return 'sql'
    return 'hash'


def header(style, newline):
    lines = {
        'java': ['/*', ' * ' + COPYRIGHT, ' * ' + LICENSE, ' */'],
        'markup': ['<!--', '  ' + COPYRIGHT, '  ' + LICENSE, '-->'],
        'sql': ['--', '-- ' + COPYRIGHT, '-- ' + LICENSE, '--'],
        'hash': ['#', '# ' + COPYRIGHT, '# ' + LICENSE, '#'],
    }[style]
    return [line + newline for line in lines]


def insertion_index(lines):
    """After what has to stay first: a shebang and coding line, an XML declaration, a doctype,
    and the '--#source' directives of a database upgrade script, which dbfunc-common reads only
    from the first lines of the file."""
    index = 0
    while index < len(lines) and lines[index].startswith('--#source'):
        index += 1
    if index:
        return index
    if lines and lines[0].startswith('#!'):
        index = 1
        if len(lines) > 1 and lines[1].startswith('#') and 'coding' in lines[1]:
            index = 2
    else:
        if index < len(lines) and lines[index].lstrip().startswith('<?xml'):
            index += 1
        if index < len(lines) and lines[index].lstrip().upper().startswith('<!DOCTYPE HTML'):
            index += 1
    return index


def needs(path):
    style = kind(path)
    if style is None:
        return None, None
    with open(path, encoding='utf-8') as stream:
        text = stream.read()
    head = text.splitlines()[:HEAD_LINES]
    if any('Copyright' in line for line in head):
        return style, None
    return style, text


def add(path):
    style, text = needs(path)
    if style is None:
        return 'skipped'
    if text is None:
        return 'present'
    lines = text.splitlines(keepends=True)
    newline = '\r\n' if lines and lines[0].endswith('\r\n') else '\n'
    for index, line in enumerate(lines[:HEAD_LINES]):
        if 'SPDX-License-Identifier' in line:
            # A license line of its own already: the copyright line goes just above it.
            prefix = line[:line.index('SPDX-License-Identifier')]
            lines.insert(index, prefix + COPYRIGHT + newline)
            break
    else:
        index = insertion_index(lines)
        lines[index:index] = header(style, newline)
    with open(path, 'w', encoding='utf-8', newline='') as stream:
        stream.write(''.join(lines))
    return 'added'


def new_files(base):
    output = subprocess.run(
        ('git', 'diff', '--name-only', '--no-renames', '--diff-filter=A', base, 'HEAD'),
        check=True, stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout
    return [line for line in output.splitlines() if line]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--base', default=DEFAULT_BASE)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()

    results = {'added': [], 'present': [], 'skipped': []}
    for path in new_files(args.base):
        if args.check:
            style, text = needs(path)
            results['skipped' if style is None else 'present' if text is None else 'added'].append(path)
        else:
            results[add(path)].append(path)

    if args.check:
        for path in results['added']:
            print('missing: ' + path)
        print('{} have a copyright header, {} lack one, {} not applicable'.format(
            len(results['present']), len(results['added']), len(results['skipped'])))
        return 1 if results['added'] else 0
    print('{} headers added, {} already present, {} not applicable'.format(
        len(results['added']), len(results['present']), len(results['skipped'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
