#!/usr/bin/python3

import os, sys, re
import string
import argparse
import json
import textwrap
import socket
import time
import glob
Toggle navigation
Toggle navigation
 Subnet Calculator
198.41.222.254
 
Input
198.41.222.254/32
CIDR
198.41.222.254/32
Input IP
198.41.222.254
CIDR IP Range
198.41.222.254 - 198.41.222.254
Input Long
3324632830
CIDR Long Range
3324632830 - 3324632830
Input Hex
C6.29.DE.FE
CIDR Hex Range
C6.29.DE.FE - C6.29.DE.FE
IPs in Range
1
Mask Bits
32
Subnet Mask
255.255.255.255
Hex Subnet Mask
FF.FF.FF.FF
IP is contained in the following CIDR Blocks
128.0.0.0/1
192.0.0.0/2
192.0.0.0/3
192.0.0.0/4
192.0.0.0/5
196.0.0.0/6
198.0.0.0/7
198.0.0.0/8
198.0.0.0/9
198.0.0.0/10
198.32.0.0/11
198.32.0.0/12
198.40.0.0/13
198.40.0.0/14
198.40.0.0/15
198.41.0.0/16
198.41.128.0/17
198.41.192.0/18
198.41.192.0/19
198.41.208.0/20
198.41.216.0/21
198.41.220.0/22
198.41.222.0/23
198.41.222.0/24
198.41.222.128/25
198.41.222.192/26
198.41.222.224/27
198.41.222.240/28
198.41.222.248/29
198.41.222.252/30
198.41.222.254/31
198.41.222.254/32
ABOUT SUBNET CALCULATOR
The subnet calculator lets you enter a subnet range (CIDR) and see IP address information about that range You can type your range directly in CIDR notation, or use the optional Mask pull-down:

74.125.227.0/29
74.125.227.0, then select Optional Mask from dropdown
This is a useful feature for service providers and network operator who frequently allocate and work with subnets. CIDR stands for Classless Inter-Domain Routing, and refers to the standard of dividing the entire IP address space into smaller networks of variable size.

Your IP is: 102.89.32.30|  Contact Terms & Conditions Site Map API Privacy Phone: (866)-MXTOOLBOX / (866)-698-6652 |  © Copyright 2004-2021, MXToolBox, Inc, All rights reserved. US Patents 10839353 B2 & 11461738 B2
 
burritos@banana-pancakes.com braunstrowman@banana-pancakes.com finnbalor@banana-pancakes.com ricflair@banana-pancakes.com randysavage@banana-pancakes.com base64

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
