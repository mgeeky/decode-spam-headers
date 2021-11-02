#!/usr/bin/python3

import os, sys, re
import string
import argparse
import json
import textwrap
import socket
import time
import glob
import base64

rules = {}
files_and_their_rules = {}
scanned = set()

FILES_PREFIX='analysis-'

def walk(path):
    global rules
    global files_and_their_rules
    global scanned

    print(f'Walking {path}...')

    for file in glob.glob(os.path.join(path, '**'), recursive=True):
        if not file.lower().endswith('.txt'):
            continue

        if file in scanned: 
            continue

        base = os.path.basename(file)
        if len(FILES_PREFIX) > 0:
            if not base.lower().startswith(FILES_PREFIX.lower()):
                continue

        scanned.add(file)

        data = ''
        with open(file) as f:
            data = f.read()

        for m in re.finditer(r'(\(\d{4,}\))', data, re.I):
            rule = m.group(1)

            if file not in files_and_their_rules.keys():
                files_and_their_rules[file] = set()

            files_and_their_rules[file].add(rule)

            if rule in rules.keys():
                if file not in rules[rule]['files']:
                    rules[rule]['count'] += 1
                    rules[rule]['files'].add(file)
            else:
                rules[rule] = {}
                rules[rule]['count'] = 1
                rules[rule]['files'] = set([file, ])

def main(argv):

    paths = []
    for i in range(len(argv)):
        arg = argv[i]
        if i == 0: continue

        if not os.path.isdir(arg):
            print('[!] input path does not exist or is not a dir! ' + arg)
            sys.exit(1)

        walk(os.path.abspath(arg))

    print(f'[.] Found {len(rules)} unique rules.:')

    for k, v in rules.items():
        if v['count'] > 1:
            print(f'\n\t- {k: <15}: occurences: {v["count"]} - files: {len(v["files"])}')

            if len(v['files']) < 6:
                for f in v['files']:
                    print('\t\t- ' + str(f))


    output = ' #  | file1                                              | file2                                              |\n'
    output+= '----+----------------------------------------------------+----------------------------------------------------+\n'

    checked = set()
    for k, v in files_and_their_rules.items():
        for k1, v1 in files_and_their_rules.items():
            if k == k1: 
                continue

            n = max(len(v.difference(v1)), len(v1.difference(v)))
            if n <= 3 and n > 0:
                if k not in checked and k1 not in checked:
                    output += f' {n: <2} | {k[-50:]: <50} | {k1[-50:]: <50} |\n'
                    checked.add(k)
                    checked.add(k1)
                    
    output+= '----+----------------------------------------------------+----------------------------------------------------+\n'

    print('\nCross-File rules differences:\n')
    print(output)

    print('\n\nFiles and rules matched:\n')

    num = 0
    s = {k: v for k, v in sorted(files_and_their_rules.items(), key=lambda item: len(item[1]))}

    for k, v in s.items():
        num += 1
        print(f'{num: <3}. Rules: {len(v): <2}, File: {k}')

    print()

if __name__ == '__main__':
    main(sys.argv)