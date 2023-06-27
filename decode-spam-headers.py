#!/usr/bin/python3

#
# This script attempts to decode SMTP headers that may contain Anti-Spam related information, clues,
# scores and other characteristics. Intention is to extract reason why the message was considered a spam,
# by combining flags and values for different headers from all around the Internet and documentation.
#
# The script might be used by System Administrators to help them understand mail deliverability obstacles,
# but also by the Offensive security consultants performing Phishing Awareness Trainings, before sending
# a campaign to analyse negative constructs in their e-mails.
#
# The script can decode 67+ different SPAM related headers (and others bringing valuable information):
#   - X-forefront-antispam-report
#   - X-exchange-antispam
#   - X-exchange-antispam-mailbox-delivery
#   - X-exchange-antispam-message-info
#   - X-microsoft-antispam-report-cfa-test
#   - Received
#   - From
#   - To
#   - Subject
#   - Thread-topic
#   - Received-spf
#   - X-mailer
#   - X-originating-ip
#   - User-agent
#   - X-forefront-antispam-report
#   - X-microsoft-antispam-mailbox-delivery
#   - X-microsoft-antispam
#   - X-exchange-antispam-report-cfa-test
#   - X-spam-status
#   - X-spam-level
#   - X-spam-flag
#   - X-spam-report
#   - X-vr-spamcause
#   - X-ovh-spam-reason
#   - X-vr-spamscore
#   - X-virus-scanned
#   - X-spam-checker-version
#   - X-ironport-av
#   - X-ironport-anti-spam-filtered
#   - X-ironport-anti-spam-result
#   - X-mimecast-spam-score
#   - Spamdiagnosticmetadata
#   - X-ms-exchange-atpmessageproperties
#   - X-msfbl
#   - X-ms-exchange-transport-endtoendlatency
#   - X-ms-oob-tlc-oobclassifiers
#   - X-ip-spam-verdict
#   - X-amp-result
#   - X-ironport-remoteip
#   - X-ironport-reputation
#   - X-sbrs
#   - X-ironport-sendergroup
#   - X-policy
#   - X-ironport-mailflowpolicy
#   - X-remote-ip
#   - X-sea-spam
#   - X-fireeye
#   - X-antiabuse
#   - X-tmase-version
#   - X-tm-as-product-ver
#   - X-tm-as-result
#   - X-imss-scan-details
#   - X-tm-as-user-approved-sender
#   - X-tm-as-user-blocked-sender
#   - X-tmase-result
#   - X-tmase-snap-result
#   - X-imss-dkim-white-list
#   - X-tm-as-result-xfilter
#   - X-tm-as-smtp
#   - X-scanned-by
#   - X-mimecast-spam-signature
#   - X-mimecast-bulk-signature
#   - X-sender-ip
#   - X-forefront-antispam-report-untrusted
#   - X-microsoft-antispam-untrusted
#   - X-sophos-senderhistory
#   - X-sophos-rescan
#   - X-MS-Exchange-CrossTenant-Id
#   - X-OriginatorOrg
#   - IronPort-Data
#   - IronPort-HdrOrdr
#   - X-DKIM
#   - DKIM-Filter
#   - X-SpamExperts-Class
#   - X-SpamExperts-Evidence
#   - X-Recommended-Action
#   - X-AppInfo
#   - X-TM-AS-MatchedID
#   - X-MS-Exchange-EnableFirstContactSafetyTip
#   - X-MS-Exchange-Organization-BypassFocusedInbox
#   - X-MS-Exchange-SkipListedInternetSender
#   - X-MS-Exchange-ExternalOriginalInternetSender
#   - X-CNFS-Analysis
#   - X-Authenticated-Sender
#   - X-Apparently-From
#   - X-Env-Sender
#   - Sender
#
# Usage:
#   ./decode-spam-headers [options] <smtp-headers.txt>
#
# NOTICE:
#   Parts of this code contain fragments copied from the following places:
#
#      1) testEmailIntelligence():
#         source: https://github.com/nquinlan/Email-Intelligence 
#         authored by: Nick Quinlan (nick@nicholasquinlan.com)
#
# Requirements:
#   - python-dateutil
#   - tldextract
#   - packaging
#   - dnspython
#   - colorama
#
# Mariusz Banach / mgeeky, '21-'22
# <mb [at] binary-offensive.com>
#

import os, sys, re
import string
import argparse
import json
import textwrap
import socket
import textwrap
import time
import atexit
import base64

from html import escape
from email import header as emailheader
from datetime import *
from dateutil.tz import *

try:
    from dateutil import parser
except ImportError:
    print('''
[!] You need to install python-dateutil: 
        # pip3 install python-dateutil
''')
    sys.exit(1)

try: 
    import colorama
except ImportError:
    print('''
[!] You need to install colorama: 
        # pip3 install colorama
''')
    sys.exit(1)

try:
    import packaging.version

except ImportError:
    print('''
[!] You need to install packaging: 
        # pip3 install packaging
''')
    sys.exit(1)

try:
    import requests
except ImportError:
    print('''
[!] You need to install requests: 
        # pip3 install requests
''')
    sys.exit(1)

try:
    import tldextract
except ImportError:
    print('''
[!] You need to install tldextract: 
        # pip3 install tldextract
''')
    sys.exit(1)

try:
    import dns.resolver

except ImportError:
    print('''
[!] You need to install dnspython: 
        # pip3 install dnspython

    If problem remains, re-install dnspython:
        # pip3 uninstall dnspython
        # pip3 install dnspython
''')
    sys.exit(1)

colorama.init()

options = {
    'debug': False,
    'verbose': False,
    'nocolor' : False,
    'log' : sys.stderr,
    'format' : 'text',
    'dont_resolve' : False,
}

class Logger:
    colors_map = {
        'red':      31, 
        'green':    32, 
        'yellow':   33,
        'blue':     34, 
        'magenta':  35, 
        'cyan':     36,
        'white':    37, 
        'grey':     38,
    }

    html_colors_map = {
        'background':'rgb(40, 44, 52)',
        'grey':      'rgb(132, 139, 149)',
        'cyan' :     'rgb(86, 182, 194)',
        'blue' :     'rgb(97, 175, 239)',
        'red' :      'rgb(224, 108, 117)',
        'magenta' :  'rgb(198, 120, 221)',
        'yellow' :   'rgb(229, 192, 123)',
        'white' :    'rgb(220, 223, 228)',
        'green' :    'rgb(108, 135, 94)',
    }

    colors_dict = {
        'error': colors_map['red'],
        'info ': colors_map['green'],
        'debug': colors_map['grey'],
        'other': colors_map['grey'],
    }

    options = {}

    def __init__(self, opts = None):
        self.options.update(Logger.options)
        if opts != None and len(opts) > 0:
            self.options.update(opts)

    @staticmethod
    def with_color(c, s):
        #return "\x1b[%dm%s\x1b[0m" % (c, s)
        return f'__COLOR_{c}__|{s}|__END_COLOR__'

    @staticmethod
    def replaceColors(s, colorizingFunc):
        pos = 0

        while pos < len(s):
            if s[pos:].startswith('__COLOR_'):
                pos += len('__COLOR_')
                pos1 = s[pos:].find('__|')

                assert pos1 != -1, "Output colors mismatch - could not find pos of end of color number!"

                c = int(s[pos:pos+pos1])
                pos += pos1 + len('__|')
                pos2 = s[pos:].find('|__END_COLOR__')

                assert pos2 != -1, "Output colors mismatch - could not find end of color marker!"

                txt = s[pos:pos+pos2]
                pos += pos2 + len('|__END_COLOR__')

                patt = f'__COLOR_{c}__|{txt}|__END_COLOR__'

                colored = colorizingFunc(c, txt)

                assert len(colored) > 0, f"Could not strip colors from phrase: ({patt})!"

                s = s.replace(patt, colored)
                pos = 0
                continue

            pos += 1

        return s

    @staticmethod
    def noColors(s):
        return Logger.replaceColors(s, lambda c, txt: txt)

        return out

    def ansiColors(s):
        return Logger.replaceColors(s, lambda c, txt: f'\x1b[{c}m{txt}\x1b[0m')

    @staticmethod
    def htmlColors(s):
        def get_col(c, txt):
            text = escape(txt)

            for k, v in Logger.colors_map.items():
                if v == c:
                    htmlCol = Logger.html_colors_map[k]
                    return f'<font class="text-{k}">{text}</font>'
            
            return text

        return Logger.replaceColors(s, get_col)

    def colored(self, txt, col):
        if self.options['nocolor']:
            return txt

        return Logger.with_color(Logger.colors_map[col], txt)
        
    # Invocation:
    #   def out(txt, mode='info ', fd=None, color=None, noprefix=False, newline=True):
    @staticmethod
    def out(txt, fd, mode='info ', **kwargs):
        if txt == None or fd == 'none':
            return 
        elif fd == None:
            raise Exception('[ERROR] Logging descriptor has not been specified!')

        args = {
            'color': None, 
            'noprefix': False, 
            'newline': True,
            'nocolor' : False
        }
        args.update(kwargs)

        if type(txt) != str:
            txt = str(txt)
            
        txt = txt.replace('\t', ' ' * 4)

        if args['nocolor']:
            col = ''
        elif args['color']:
            col = args['color']
            if type(col) == str and col in Logger.colors_map.keys():
                col = Logger.colors_map[col]
        else:
            col = Logger.colors_dict.setdefault(mode, Logger.colors_map['grey'])

        prefix = ''
        if mode:
            mode = '[%s] ' % mode
            
        if not args['noprefix']:
            if args['nocolor']:
                prefix = mode.upper()
            else:
                prefix = Logger.with_color(Logger.colors_dict['other'], '%s' 
                % (mode.upper()))
        
        nl = ''
        if 'newline' in args:
            if args['newline']:
                nl = '\n'

        if 'force_stdout' in args:
            fd = sys.stdout

        to_write = ''

        if type(fd) == str:
            prefix2 = ''
            if mode: 
                prefix2 = '%s' % (mode.upper())
            prefix2 + txt + nl

        else:
            if args['nocolor']:
                to_write = prefix + txt + nl
            else:
                to_write = prefix + Logger.with_color(col, txt) + nl

        to_write = Logger.ansiColors(to_write)

        if type(fd) == str:
            with open(fd, 'a') as f:
                f.write(to_write)
                f.flush()

        else:
            fd.write(to_write)

    # Info shall be used as an ordinary logging facility, for every desired output.
    def info(self, txt, forced = False, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        if forced or (self.options['verbose'] or \
            self.options['debug'] ) \
            or (type(self.options['log']) == str and self.options['log'] != 'none'):
            Logger.out(txt, self.options['log'], 'info', **kwargs)

    def text(self, txt, **kwargs):
        kwargs['noPrefix'] = True
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], '', **kwargs)

    def dbg(self, txt, **kwargs):
        if self.options['debug']:
            if self.options['format'] == 'html':
                txt = f'<!-- {txt} -->'

            kwargs['nocolor'] = self.options['nocolor']
            Logger.out(txt, self.options['log'], 'debug', **kwargs)

    def err(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)

    def fatal(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)
        os._exit(1)

logger = Logger(options)

class Verstring(object):
    def __init__(self, name, date, *versions):
        self.name = name
        self.date = date
        self.version = versions[0].split(' ')[0]

    def __eq__(self, other):
        if isinstance(other, Verstring):
            return packaging.version.parse(self.version) == packaging.version.parse(other.version) \
            and self.name == other.name
        elif isinstance(other, str):
            return packaging.version.parse(self.version) == packaging.version.parse(other)

    def __lt__(self, other):
        return packaging.version.parse(self.version) < packaging.version.parse(other.version)

    def __str__(self):
        return f'{self.name}; {self.date}; {self.version}'


class SMTPHeadersAnalysis:
    bad_keywords = (
        'gophish', 'phishingfrenzy', 'frenzy', 'king-phisher', 'phisher', 
        'speedphishing', 
    )

    Dodgy_User_Names = (
        'action', 'postmaster', 'root', 'admin', 'administrator', 'offer',
        'test', 'it', 'account', 'hr', 'job', 'relay', 'robot', 'help', 'catchall',
        'guest', 'spam', 'abuse', 'all', 'contact', 'nobody', 'auto', 'db', 'web',  'no-reply', 'noreply',
        'anonymous', 'amazon', 'microsoft', 'google', 'mailbox', 'group', 

    )

    Header_Keywords_That_May_Contain_Spam_Info = (
        'spam', 'phishing', 'bulk', 'attack', 'defend', 'assassin', 'virus', 'scan', 'mimecast', 
        'ironport', 'forefront', '360totalsecurity', 'acronis', 'adaware', 'adsbot-google', 
        'aegislab', 'ahnlab', 'altavista', 'anti-virus', 'antivirus', 'antiy', 'apexone', 
        'appengine-google', 'arcabit', 'avast', 'avg', 'avira', 'baidu', 'baiduspider', 
        'barracuda', 'bingbot', 'bitdefender', 'bitdefender', 'bluvector', 'carbon', 
        'carbonblack', 'check point', 'checkpoint', 'clamav', 'code42', 'comodo', 'countercept', 
        'countertack', 'crowdstrike', 'crowdstrike', 'curl', 'cybereason', 'cybereason', 
        'cylance', 'cylance', 'cynet360', 'cyren', 'defender', 'druva', 'drweb', 'duckduckbot', 
        'egambit', 'emsisoft', 'emsisoft', 'encase', 'endgame', 'endgame', 'ensilo', 'escan', 
        'eset', 'exabot', 'f-secure', 'facebookexternalhit', 'falcon', 'fidelis', 'fireeye', 
        'forcepoint', 'fortigate', 'fortil', 'fortinet', 'gdata', 'gdata', 'googlebot', 
        'gravityzone', 'huntress', 'ia_archiver', 'ikarussecurity', 'ivanti', 'juniper', 
        'k7antivirus', 'k7computing', 'kaspersky', 'kingsoft', 'lightcyber', 'lynx', 
        'malwarebytes', 'mcafee', 'mj12bot', 'msnbot', 'nanoav', 'netwitness', 'paloalto', 
        'paloaltonetworks', 'panda', 'proofpoint', 'python-urllib', 'scanner', 'scanning', 
        'secureage', 'secureworks', 'security', 'sentinelone', 'sentinelone', 'simplepie', 
        'slackbot-linkexpanding', 'slurp', 'sogou', 'sonicwall', 'sophos', 'superantispyware', 
        'symantec', 'tachyon', 'tencent', 'totaldefense', 'trapmine', 'trend micro', 'trendmicro', 
        'trusteer', 'trustlook', 'virusblokada', 'virustotal', 'virustotalcloud', 'webroot', 
        'yandex', 'yandexbot', 'zillya', 'zonealarm', 'zscaler', '-sea-', 'perlmx', 'trustwave',
        'mailmarshal', 'tmase', 'startscan', 'fe-etp', 'jemd', 'suspicious', 'grey', 'infected', 'unscannable',
        'dlp-', 'sanitize', 'mailscan', 'barracuda', 'clearswift', 'messagelabs', 'msw-jemd', 'fe-etp', 'symc-ess',
        'starscan', 'mailcontrol', 'spamexpert', 'X-Fuglu',
    )

    Interesting_Headers = (
        'mailgun', 'sendgrid', 'mailchimp', 'x-ses', 'x-avas', 'X-Gmail-Labels', 'X-vrfbldomain',
        'mandrill', 'bulk',  'sendinblue', 'amazonses', 'mailjet', 'postmark', 'postfix', 'dovecot',  'roundcube',
        'seg', '-IP', 'crosspremises', 'brightmail', 'check', 'exim',  'postfix',   'exchange', 'microsoft', 'office365',
        'dovecot', 'sendmail', 'report', 'status', 'benchmarkemail', 'bronto', 'X-Complaints-To',
        'X-Roving-ID', 'X-DynectEmail-Msg', 'X-elqPod', 'X-EMV-MemberId', 'e2ma', 'fishbowl', 'eloop', 'X-Google-Appengine-App-Id',
        'X-ICPINFO', 'x-locaweb-id', 'X-MC-User', 'mailersend', 'MailiGen', 'Mandrill', 'MarketoID', 'X-Messagebus-Info',
        'Mixmax', 'X-PM-Message-Id', 'postmark', 'X-rext', 'responsys', 'X-SFDC-User', 'salesforce', 'x-sg-', 'x-sendgrid-',
        'silverpop', '.mkt', 'X-SMTPCOM-Tracking-Number', 'X-vrfbldomain', 'verticalresponse',
        'yesmail', 'logon', 'safelink', 'safeattach', 'appinfo', 'X-XS4ALL-', 'client-ip', 'porn',
        'X-Newsletter'
    )

    Security_Appliances_And_Their_Headers = \
    (
        ('Barracuda Email Security'                              , 'X-Barracuda-'),
        ('Cisco Advanced Malware Protection (AMP)'               , 'X-Amp-'),
        ('Cisco IronPort / Email Security Appliance (ESA)'       , 'X-Policy'),
        ('Cisco IronPort / Email Security Appliance (ESA)'       , 'X-SBRS'),
        ('Cisco IronPort'                                        , 'X-IronPort-'),
        ('Office365'                                             , 'X-.+Tenant.+'),
        ('Office365'                                             , 'X-MS-Exchange-Organization'),
        ('Office365'                                             , 'X-MS-Exchange-CrossTenant-Id'),
        ('Exchange Online Protection'                            , 'X-EOP'),
        ('Exchange Online Protection'                            , 'X-MS-Exchange-'),
        ('Exchange Online Protection - First Contact Safety'     , 'X-.+-EnableFirstContactSafetyTip'),
        ('Exchange Online Protection - Enhanced Filtering'       , 'X-.+-SkipListedInternetSender'),
        ('Exchange Online Protection - Enhanced Filtering'       , 'X-.+-ExternalOriginalInternetSender'),
        ('Exchange Server 2016 Anti-Spam'                        , 'SpamDiagnostic'),
        ('FireEye Email Security Solution'                       , 'X-FE-'),
        ('FireEye Email Security Solution'                       , 'X-FEAS-'),
        ('FireEye Email Security Solution'                       , 'X-FireEye'),
        ('Mimecast'                                              , 'X-Mimecast-'),
        ('Fuglu - mail scanner for postfix'                      , 'X-Fuglu'),
        ('MS Defender Advanced Threat Protection - Safe Links'   , '-ATPSafeLinks'),
        ('MS Defender Advanced Threat Protection'                , 'X-MS.+-Atp'),
        ('MS Defender for Office365'                             , '-Safelinks'),
        ('MS ForeFront Anti-Spam'                                , 'X-Forefront-Antispam'),
        ('MS ForeFront Anti-Spam'                                , 'X-Microsoft-Antispam'),
        ('n-able Mail Assure (SpamExperts)'                      , 'SpamExperts-'),
        ('OVH Anti-Spam'                                         , 'X-Ovh-'),
        ('OVH Anti-Spam'                                         , 'X-VR-'),
        ('Proofpoint Email Protection'                           , 'X-Proofpoint'),
        ('Sophos Email Appliance (PureMessage)'                  , 'X-SEA-'),
        ('SpamAssassin'                                          , 'X-IP-Spam-'),
        ('SpamAssassin'                                          , 'X-Spam-'),
        ('Symantec Email Security'                               , 'X-SpamInfo'), 
        ('Symantec Email Security'                               , 'X-SpamReason'), 
        ('Symantec Email Security'                               , 'X-Brightmail-Tracker'), 
        ('Symantec Email Security'                               , 'X-StarScan'), 
        ('Symantec Email Security'                               , 'X-SYMC-'), 
        ('Trend Micro Anti-Spam'                                 , 'X-TM-AS-'),
        ('Trend Micro Anti-Spam'                                 , 'X-TMASE-'),
        ('Trend Micro InterScan Messaging Security'              , 'X-IMSS-'),
        ('Cloudmark Security Platform'                           , 'X-CNFS-'),
        ('Cloudmark Security Platform'                           , 'X-CMAE-'),
        ('VIPRE Email Security'                                  , 'X-Vipre-'),
        ('Sunbelt Software Ninja Email Security'                 , 'X-Ninja-'),
        ('WP.pl / o2.pl Email Scanner'                           , 'X-WP-AV-'),
    )

    Security_Appliances_And_Their_Values = \
    (
        ('Exchange Online Protection'                            , '.protection.outlook.com'),
    )

    Headers_Known_For_Breaking_Line = (
        'Received',
        'Authentication-Results',
        'Received-SPF',
        'DKIM-Signature',
        'X-Google-DKIM-Signature',
        'X-GM-Message-State',
        'Subject',
        'X-MS-Exchange-Organization-ExpirationStartTime',
        'X-MS-Exchange-Organization-Network-Message-Id',
        'X-Forefront-Antispam-Report',
        'X-MS-Exchange-CrossTenant-OriginalArrivalTime',
        'X-Microsoft-Antispam-Mailbox-Delivery',
        'X-Microsoft-Antispam-Message-Info'
    )

    #
    # This array will be (partially) dynamically adjusted by the script by SMTPHeadersAnalysis.getHeader method.
    #
    # Add here header names that are processed by the script, but not passed to `getHeader` method
    # in order to skip them from "Other Interesting Headers" sweep scan.
    #
    Handled_Spam_Headers = [
        'X-Forefront-Antispam-Report',
        'X-Exchange-Antispam',
        'X-Exchange-Antispam-Mailbox-Delivery',
        'X-Exchange-Antispam-Message-Info',
        'X-Microsoft-Antispam-Report-CFA-Test',
    ]

    auth_result = {
        'none': 'The message was not signed.',
        'pass': logger.colored('The message was signed, the signature or signatures were acceptable to the ADMD, and the signature(s) passed verification tests.', 'green'),
        'fail': logger.colored('The message was signed and the signature or signatures were acceptable to the ADMD, but they failed the verification test(s).', 'red'),
        'policy': 'The message was signed, but some aspect of the signature or signatures was not acceptable to the ADMD.',
        'neutral': logger.colored('The message was signed, but the signature or signatures contained syntax errors or were not otherwise able to be processed.', 'magenta'),
        'temperror': logger.colored('The message could not be verified due to some error that is likely transient in nature, such as a temporary inability to retrieve a public key.', 'red'),
        'permerror': logger.colored('The message could not be verified due to some error that is unrecoverable, such as a required header field being absent.', 'red'), 
    }

    IronPort_AV = {
        'i' : (
            'Version Information',
            (
                'Product Version',
                'Number of IDEs',
                'IDE Serial   '
            )
        ),

        'E' : (
            'AV scanning engine',
            ''
        ),

        'e' : (
            'Errors',
            {
                "i" : 'ignored',
                "u" : logger.colored('unscannable', 'red'),
                "e" : 'encrypted',
                "t" : 'timeout',
                "f" : 'fatal',
                "j" : 'savi-bug (ignored)',
                "s" : 'savi-bug (unscannable)',
                "z" : 'unknown',
            }
        ),

        'v' : (
            'Virus List',
            (
                'extension',
                'type code list'
            )
        ),

        'd' : (
            'File details',
            (
                'extension',
                'type code list'
            )
        ),

        'a' : (
            'Message actions',
            {
                '_map' : {
                    'N' : 'notification',
                    'H' : 'headers',
                    'T' : 'time',
                    ':' : 'action'
                },

                'action' : {
                    "a" : 'archived ?',
                    "s" : logger.colored('sent', 'green'),
                    "d" : logger.colored('dropped', 'red'),
                    "f" : 'forwarded',
                    "x" : 'certain errors (timed-out, rpc conn fails, etc)',
                },

                'notification' : {
                    "s" : 'sender',
                    "r" : 'recipient',
                    "o" : 'other',
                },

                'headers' : {
                    "s" : 'subject modified',
                    "h" : 'custom header modified',
                },

                'time' : {
                },
            }
        )
    }

    Aterisk_Risk_Score = {
        '*' :      logger.colored('lowest risk associated', 'green'),
        '**' :     logger.colored('low risk associated', 'green'),
        '***' :    logger.colored('moderately low risk associated', 'yellow'),
        '****' :   logger.colored('moderately high risk associated', 'yellow'),
        '*****' :  logger.colored('high risk associated', 'red'),
        '******' : logger.colored('highest risk associated', 'red'),
    }

    AMP_Results = {
        'CLEAN' :       logger.colored('No malware detected.', "green"),
        'MALICIOUS' :   logger.colored('Malware detected.', "red"),
        'UNKNOWN' :     logger.colored('Could not categorize the message.', "magenta"),
        'UNSCANNABLE' : logger.colored('Could not scan the message.', "yellow"),
    }

    Forefront_Antispam_Report = {
        'ARC' : (
            'ARC Protocol',
            {
                'AAR': 'Records the content of the Authentication-results header from DMARC.',
                'AMS': 'Includes cryptographic signatures of the message.',
                'AS': 'Includes cryptographic signatures of the message headers'
            }
        ),

        'CAT' : (
            'The category of protection policy',
            {
                'BULK': logger.colored('Bulk', 'red'),
                'DIMP': logger.colored('Domain Impersonation', 'red'),
                'GIMP': logger.colored('Mailbox intelligence based impersonation', 'red'),
                'HPHSH': logger.colored('High confidence phishing', 'red'),
                'HPHISH': logger.colored('High confidence phishing', 'red'),
                'HSPM': logger.colored('High confidence spam', 'red'),
                'MALW': logger.colored('Malware', 'red'),
                'PHSH': logger.colored('Phishing', 'red'),
                'SPM': logger.colored('Spam', 'red'),
                'SPOOF': logger.colored('Spoofing', 'red'),
                'UIMP': logger.colored('User Impersonation', 'red'),
                'AMP': logger.colored('Anti-malware', 'red'),
                'SAP': logger.colored('Safe attachments', 'green'),
                'OSPM': logger.colored('Outbound spam', 'red'),
                'NONE': logger.colored('Clean message', 'green'),
            }
        ),

        'CTRY' : (
            'The source country as determined by the connecting IP address',
            ''
        ),

        'H' : (
            'The HELO or EHLO string of the connecting email server.',
            ''
        ),

        'IPV' : (
            'Ingress Peer Verification status',
            {
                'CAL' : logger.colored('Source IP address was Configured in Allowed List (CAL)', 'green'),
                'NLI' : 'The IP address was not found on any IP reputation list.',
            }
        ),

        'EFV' : (
            'Egress F(?) Verification status',
            {
                'CAL' : logger.colored('Source IP address was Configured in Allowed List (CAL)', 'green'),
                'NLI' : 'The IP address was not found on any IP reputation list.',
            }
        ),

        'DIR' : (
            'Direction of email verification',
            {
                'INB' : 'Inbound email verification',
                'OUT' : 'Outbound email verification',
                'OUB' : 'Outbound email verification',
                'OTB' : 'Outbound email verification',
            }
        ),

        'LANG' : (
            'The language in which the message was written',
            ''
        ),

        'PTR' : (
            'Reverse DNS of the Connecting IP peer\'s address',
            ''
        ),

        'SFTY' : (
            'The message was identified as phishing',
            {
                '9.19': logger.colored('Domain impersonation. The sending domain is attempting to impersonate a protected domain', 'red'),

                '9.20' : logger.colored('User impersonation. The sending user is attempting to impersonate a user in the recipient\'s organization', 'red'),
            }
        ),

        'SRV' : (
            'Bulk Email analysis results',
            {
                'BULK' : logger.colored('The message was identified as bulk email by spam filtering and the bulk complaint level (BCL) threshold', 'red'),
            }
        ),

        'SFV' : (
            'Message Filtering',
            {
                'BLK' : logger.colored('Filtering was skipped and the message was blocked because it was sent from an address in a user\'s Blocked Senders list.', 'red'),
                'NSPM' : logger.colored('Spam filtering marked the message as non-spam and the message was sent to the intended recipients.', 'green'),
                'SFE' : logger.colored('Filtering was skipped and the message was allowed because it was sent from an address in a user\'s Safe Senders list.', 'green'),
                'SKA' : logger.colored('The message skipped spam filtering and was delivered to the Inbox because the sender was in the allowed senders list or allowed domains list in an anti-spam policy.', 'green'),
                'SKB' : logger.colored('The message was marked as spam because it matched a sender in the blocked senders list or blocked domains list in an anti-spam policy.', 'red'),
                'SKI' : 'Similar to SFV:SKN, the message skipped spam filtering for another reason (for example, an intra-organizational email within a tenant).',
                'SKN' : logger.colored('The message was marked as non-spam prior to being processed by spam filtering. For example, the message was marked as SCL -1 or Bypass spam filtering by a mail flow rule.', 'green'),
                'SKQ' : logger.colored('The message was released from the quarantine and was sent to the intended recipients.', 'cyan'),
                'SKS' : logger.colored('The message was marked as spam prior to being processed by spam filtering. For example, the message was marked as SCL 5 to 9 by a mail flow rule.', 'red'),
                'SPM' : logger.colored('The message was marked as spam by spam filtering.', 'red'),
            }
        ),
    }

    Barracuda_Score_Thresholds = [
        [0.0, 2.99, logger.colored('Delivered to Inbox', 'green')],
        [3.0, 4.99, logger.colored('Delivered to Inbox. Subject line tagged with [Suspected SPAM]', 'yellow')],
        [5.0, 6.99, logger.colored('Delivered to Barracuda Quarantine Inbox', 'red')],
        [7.0, 10.0, logger.colored('Blocked from delivery', 'red')],
    ]

    Barracuda_Aggressive_Score_Thresholds = [
        [0.0, 1.99, logger.colored('Delivered to Inbox', 'green')],
        [2.0, 3.49, logger.colored('Delivered to Inbox. Subject line tagged with [SPAM?]', 'yellow')],
        [3.5, 5.00, logger.colored('Delivered to Barracuda Quarantine Inbox', 'red')],
        [5.1, 10.0, logger.colored('Blocked from delivery', 'red')],
    ]

    Trend_Type_AntiSpam = {
        1 : logger.colored('Spam', 'red'),
        2 : logger.colored('Phishing', 'red'),
    }

    Spam_Diagnostics_Metadata = {
        'NSPM' : logger.colored('Not Spam', 'green'),
        'SPAM' : logger.colored('SPAM', 'red'),
    }


    #
    # Below rules were collected solely in a trial-and-error manner or by scraping any 
    # pieces of information from all around the Internet.
    #
    # They do not represent the actual Anti-Spam rule name or context and surely represent 
    # something close to what is understood (or they may have totally different meaning).
    # 
    # Until we'll be able to review anti-spam rules documention, there is no viable mean to map
    # rule ID to its meaning.
    #

    Anti_Spam_Rules_ReverseEngineered = \
    {
        '35100500006' : logger.colored('(SPAM) Message contained embedded image.', 'red'),

        # https://docs.microsoft.com/en-us/answers/questions/416100/what-is-meanings-of-39x-microsoft-antispam-mailbox.html
        '520007050' : logger.colored('(SPAM) Moved message to Spam and created Email Rule to move messages from this particular sender to Junk.', 'red'),

        # triggered on an empty mail with subject being: "test123 - viagra"
        '162623004' : 'Subject line contained suspicious words (like Viagra).',

        # triggered on mail with subject "test123" and body being single word "viagra"
        '19618925003' : 'Mail body contained suspicious words (like Viagra).',

        # triggered on mail with empty body and subject "Click here"
        '28233001' : 'Subject line contained suspicious words luring action (ex. "Click here"). ',

        # triggered on a mail with test subject and 1500 words of http://nietzsche-ipsum.com/
        '30864003' : 'Mail body contained a lot of text (more than 10.000 characters).',

        # mails that had simple message such as "Hello world" triggered this rule, whereas mails with
        # more than 150 words did not.
        '564344004' : 'HTML mail body with less than 150 words of text (not sure how much less though)',

        # message was sent with a basic html and only one <u> tag in body.
        '67856001' : 'HTML mail body contained underline <u> tag.',

        # message with html,head,body and body containing simple text with no b/i/u formatting.
        '579124003' : 'HTML mail body contained text, but no text formatting (<b>, <i>, <u>) was present',

        # This is a strong signal. Mails without <a> doesnt have this rule.
        '166002' : 'HTML mail body contained URL <a> link.',

        # Message contained <a href="https://something.com/file.html?parameter=value" - GET parameter with value.
        '21615005' : 'Mail body contained <a> tag with URL containing GET parameter: ex. href="https://foo.bar/file?aaa=bbb"',

        # Message contained <a href="https://something.com/file.html?parameter=https://another.com/website" 
        # - GET parameter with value, being a URL to another website
        '45080400002' : 'Something about <a> tag\'s URL. Possibly it contained GET parameter with value of another URL: ex. href="https://foo.bar/file?aaa=https://baz.xyz/"',

        # Message contained <a> with href pointing to a file with dangerous extension, such as file.exe
        '460985005' : 'Mail body contained HTML <a> tag with href URL pointing to a file with dangerous extension (such as .exe)',

        #
        # Message1: GoPhish -> VPS 587/tcp redirector -> smtp.gmail.com:587 -> target
        # Message2: GoPhish -> VPS 587/tcp redirector -> smtp-relay.gmail.com:587 -> target
        #
        # These were the only differences I spotted:
        #   Message1 - FirstHop Gmail SMTP Received with ESMTPS.
        #   Message2 - FirstHop Gmail SMTP-Relay Received with ESMTPSA.
        #
        '121216002' : 'First Hop MTA SMTP Server used as a SMTP Relay. It\'s known to originate e-mails, but here it acted as a Relay. Or maybe due to use of "with ESMTPSA" instead of ESMTPS?',

        # Triggered on message with <a> added to HTML: <a href="https://support.spotify.com/is-en/">https://www.reddit.com/</a>
        '966005' : 'Mail body contained link tag with potentially masqueraded URL: <a href="https://attacker.com">https://example.com</a>',

        #
        # Message1: GoPhish EC2 -> another EC2 with socat to smtp.gmail.com:587 (authenticated) -> Target
        # Message2: GoPhish EC2 -> Gsuite -> Target
        #
        # Subject, mail body were exactly the same.
        #
        # Below two rules were added to the second message. My understanding is that they're somehow referring
        # to the reputation of the first-hop server, maybe reverse-DNS resolution.
        #
        '5002400100002' : "(GUESSING) Somehow related to First Hop server reputation, it's reverse-PTR resolution or domain impersonation",
        '58800400005'   : "(GUESSING) Somehow related to First Hop server reputation, it's reverse-PTR resolution or domain impersonation",

        '19625305002' : '(GUESSING) Something to do with the HTML code and used tags/structures',
        '43540500002' : '(GUESSING) Something to do with the HTML code and used tags/structures',

        '460985005' : '(GUESSING) Something to do with either more-complex HTML code or with the <a> tag and its URL.',

        # Triggered on an empty text message, subject "test" - that was marked with "Domain Impersonation", however 
        # ForeFront Anti-Spam headers did not support that Domain Impersonation. Weird.
        '22186003' : '(GUESSING) Something to do with either Text message (non-HTML) or probable Domain Impersonation',

        # Found by @ipSlav (https://github.com/mgeeky/decode-spam-headers/issues/15)
        '42882007' : 'Missing Reply-To Address. Might be fixed by adding -ReplyTo flag to Send-MailMessage',
        '78352004' : 'Missing Reply-To Address. Might be fixed by adding -ReplyTo flag to Send-MailMessage',
    }

    ForeFront_Spam_Confidence_Levels = {
        -1 : (False, logger.colored('The message skipped spam filtering. WHITELISTED.', 'green')),
        0 : (False, logger.colored('Spam filtering determined the message was not spam.', 'green')),
        1 : (False, 'The message skipped spam filtering'),
        5 : (True, logger.colored('Spam filtering marked the message as Spam', 'red')),
        6 : (True, logger.colored('Spam filtering marked the message as Spam', 'red')),
        9 : (True, logger.colored('Spam filtering marked the message as High confidence spam', 'red')),
    }

    ForeFront_Phishing_Confidence_Levels = {
        1 : (False, 'The message content isn\'t likely to be phishing'),
        2 : (False, 'The message content isn\'t likely to be phishing'),
        3 : (False, 'The message content isn\'t likely to be phishing'),
        4 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        5 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        6 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        7 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        8 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
    }

    ForeFront_Bulk_Confidence_Levels = {
        0 : logger.colored('The message isn\'t from a bulk sender.', 'green'),
        1 : logger.colored('The message is from a bulk sender that generates few complaints.', 'yellow'),
        2 : logger.colored('The message is from a bulk sender that generates few complaints.', 'yellow'),
        3 : logger.colored('The message is from a bulk sender that generates few complaints.', 'yellow'),
        4 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        5 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        6 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        7 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        8 : logger.colored('The message is from a bulk sender that generates a high number of complaints.', 'red'),
        9 : logger.colored('The message is from a bulk sender that generates a high number of complaints.', 'red'),
    }

    ATP_Message_Properties = {
        'SA' : 'Safe Attachments',
        'SL' : 'Safe Links',
    }

    TLCOOBClassifiers = {
        'OLM' : (
            '',
            {

            }
        )
    }

    SpamExperts_Classes = {
        'spam'   : logger.colored("system was not confident enough to block the message", "red"),
        'unsure' : logger.colored("system was not confident enough to block the message", "magenta"),
        'ham'    : logger.colored("", "yellow"),
    }

    SpamExperts_Actions = {
        'accept' : logger.colored("Message is accepted.", "green"),
        'drop'   : logger.colored("Message is dropped.", "red"),
    }

    SEA_Spam_Fields = {
        'gauge' : 'Spam Message Gauge result',
        'probability' : 'Spam Probability (100% - certain spam)',
        'report' : 'Anti-Spam rules that matched the message along with their probability',
    }

    SpamAssassin_Spam_Status = (
        'SpamAssassin spam evaluation status report',
        {
            '_result' : 'Whether the message is Spam',
            'score' : 'Total score for the message (negative if whitelisted)',
            'required' : 'The score that would be required to be classed as spam',
            'tests' : 'List of tests that returned non-zero value',
            'autolearn' : 'Whether autolearn learned the message as spam or ham',
            'version' : 'Version of SpamAssassin used',
            'hits' : 'Number of characteristics considering this message as Spam',
            'tagged_above' : 'Tag message with SpamAssassin report if above threshold',
        }
    )

    Cisco_Predefined_MailFlow_Policies = {
        '$TRUSTED' : logger.colored('Mails from this sender are TRUSTED and will not be scanned by Anti-Spam or Anti-Virus.', 'green'),
        '$BLOCKED' : logger.colored('Mails from this sender are BLOCKED', 'red'),
        '$THROTTLED' : logger.colored('Mails from this sender are slowed down because they were considered suspicious. Messages will be scanned.', 'magenta'),
        '$ACCEPTED' : logger.colored('Mail flow policies were undecided about the sender so they accepted the message. Message will be scanned and reputation evaluated.', 'green'),
    }

    Forefront_Antispam_Delivery = {
        'dest' : (
            'Destination where message should be placed',
            {
                'I' : logger.colored('Inbox directory', 'green'),
                'J' : logger.colored('JUNK directory', 'red'),
                'C' : logger.colored('Custom directory', 'yellow'),
            }
        ),

        'auth' : (
            'Message originating from Authenticated sender',
            {
                '0' : 'Not Authenticated',
                '1' : 'Authenticated',
            }
        ),

        'ucf' : (
            'User Custom Flow (?) - custom mail flow rule applied on message?',
            {
                '0' : 'No user custom mail rule applied.',
                '1' : logger.colored('User custom mail rule applied.', "yellow"),
            }
        ),

        'jmr' : (
            'Junk Mail Rule (?) - mail considered as Spam by previous, existing mail rules?',
            {
                '0' : logger.colored('Mail not marked as Junk by mail rules.', 'cyan'),
                '1' : logger.colored('Mail marked as Junk by mail rules.', 'red'),
            }
        ),

        'OFR' : (
            'Outlook Filter Rules applied on this Message',
            {
                'ExclusiveSettings' : '',
                'CustomRules' : logger.colored('An existing folder move rule was applied on this message.', 'yellow'),
                'SpamFilterAuthJ': logger.colored('This message was marked as spam using a junk filter other than the Outlook Junk Email filter.', 'yellow'),
            } 
        ),

        'RF' : (
            'Email Rules',
            {
                'JunkEmail' : logger.colored('Mail marked as Junk and moved to Junk folder', 'red'),
            }
        ),

        'abwl' : (
            '"AB" Whitelist (?)',
            {
                '0' : 'Not whitelisted (?)',
                '1' : 'Whitelisted (?)',
            }
        ),

        'wl' : (
            'Message was whitelisted (?)',
            {
                '0' : 'Message was not whitelisted',
                '1' : logger.colored('Message was whitelisted', 'green'),
            }
        ),

        'pcwl' : (
            '"PC" Whitelist (?)',
            {
                '0' : 'Not whitelisted (?)',
                '1' : 'Whitelisted (?)',
            }
        ),

        'kl' : (
            'Unknown',
            {
                '0' : 'Unknown',
                '1' : 'Unknown',
            }
        ),

        'iwl' : (
            '"I" Whitelist (?)',
            {
                '0' : 'Not whitelisted (?)',
                '1' : 'Whitelisted (?)',
            }
        ),

        'dwl' : (
            'Domain-based Whitelist',
            {
                '0' : 'Sender\'s Domain was not whitelisted',
                '1' : logger.colored('Sender\'s Domain was whitelisted', 'green'),
            }
        ),

        'dkl' : (
            'Unknown',
            {
                '0' : 'Unknown',
                '1' : 'Unknown',
            }
        ),

        'rwl' : (
            '"R" Whitelist (?)',
            {
                '0' : 'Not whitelisted (?)',
                '1' : 'Whitelisted (?)',
            }
        ),

        'ex' : (
            'Unknown',
            {
                '0' : 'Unknown',
                '1' : 'Unknown',
            }
        ),
    }


    #
    # Based on:
    #    https://journeys.autopilotapp.com/blog/email-spam-trigger-words/
    #    https://www.activecampaign.com/blog/spam-words
    #    https://blog.hubspot.com/blog/tabid/6307/bid/30684/the-ultimate-list-of-email-spam-trigger-words.aspx
    #
    Suspicious_Words = {
        'Manipulative': (
            'creating unnecessary urgency or pressure',
            (
                "Act now", "Action", "Apply now", "Apply online", "Buy", "Buy direct", "Call", "Call now", "Click here",
                "Clearance", "Click here", "Do it today", "Don't delete", "Drastically reduced", "Exclusive deal", "Expire",
                "Get", "Get it now", "Get started now", "Important information regarding", "Instant", "Limited time",
                "New customers only", "Now only", "Offer expires", "Once in a lifetime", "Order now", "Please read",
                "Special promotion", "Take action", "This won't last", "Urgent", "While stocks last"
            )
        ),
        
        'Needy' : (
            'sounding desperate or exaggerated claims',
            (
                "All-new", "Bargain", "Best price", "Bonus", "Email marketing", "Free", "For instant access", "Free gift",
                "Free trial", "Have you been turned down?", "Great offer", "Join millions of Americans", "Incredible deal",
                "Prize", "Satisfaction guaranteed", "Will not believe your eyes"
            )
        ),
        
        'Sleazy' : (
            'being too pushy',
            (
                "As seen on", "Click here", "Click below", "Deal", "Direct email", "Direct marketing", "Do it today",
                "Order now", "Order today", "Unlimited", "What are you waiting for?", "Visit our website"
            )
        ),
        
        'Cheap' : (
            'no pre-qualifications, everybody wins',
            (
                "Acceptance", "Access", "Avoid bankruptcy", "Boss", "Cancel", "Card accepted", "Certified",
                "Cheap", "Compare", "Compare rates", "Congratulations", "Credit card offers", "Cures", "Dear ",
                "Dear friend", "Drastically reduced", "Easy terms", "Free grant money", "Free hosting", "Free info",
                "Free membership", "Friend", "Get out of debt", "Giving away", "Guarantee", "Guaranteed",
                "Have you been turned down?", "Hello", "Information you requested", "Join millions", "No age restrictions", 
                "No catch", "No experience", "No obligation", "No purchase necessary", "No questions asked", 
                "No strings attached", "Offer", "Opportunity", "Save big", "Winner", "Winning", "Won", "You are a winner!",
                "You've been selected!"
            )
        ),
        
        'Far-fetched' : (
            'statements that are too good to be true',
            (
                "Additional income", "All-natural", "Amazing", "Be your own boss", "Big bucks", "Billion",
                "Billion dollars", "Cash", "Cash bonus", "Consolidate debt and credit", "Consolidate your debt", 
                "Double your income", "Earn", "Earn cash", "Earn extra cash", "Eliminate bad credit", "Eliminate debt",
                "Extra", "Fantastic deal", "Financial freedom", "Financially independent", "Free investment", "Free money",
                "Get paid", "Home", "Home-based", "Income", "Increase sales", "Increase traffic", "Lose", "Lose weight",
                "Money back", "No catch", "No fees", "No hidden costs", "No strings attached", "Potential earnings", 
                "Pure profit", "Removes wrinkles", "Reverses aging", "Risk-free", "Serious cash", "Stop snoring",
                "Vacation", "Vacation offers", "Weekend getaway", "Weight loss", "While you sleep", "Work from home"
            )
        ),

        'Exaggeration' : (
            'exaggerated claims and promises',
            (
                "100% more", "100% free", "100% satisfied", "Additional income", "Be your own boss", "Best price",
                "Big bucks", "Billion", "Cash bonus", "Cents on the dollar", "Consolidate debt", "Double your cash",
                "Double your income", "Earn extra cash", "Earn money", "Eliminate bad credit", "Extra cash", "Extra income",
                "Expect to earn", "Fast cash", "Financial freedom", "Free access", "Free consultation", "Free gift",
                "Free hosting", "Free info", "Free investment", "Free membership", "Free money", "Free preview", "Free quote",
                "Free trial", "Full refund", "Get out of debt", "Get paid", "Giveaway", "Guaranteed", "Increase sales",
                "Increase traffic", "Incredible deal", "Lower rates", "Lowest price", "Make money", "Million dollars", "Miracle",
                "Money back", "Once in a lifetime", "One time", "Pennies a day", "Potential earnings", "Prize",
                "Promise", "Pure profit", "Risk-free", "Satisfaction guaranteed", "Save big money", "Save up to", "Special promotion",
            )
        ),

        'Urgency' : (
            'create unnecessary urgency and pressure',
            (
                "Act now", "Apply now", "Become a member", "Call now", "Click below", "Click here", "Get it now",
                "Do it today", "Don’t delete", "Exclusive deal", "Get started now", "Important information regarding", 
                "Information you requested", "Instant", "Limited time", "New customers only", "Order now", "Please read",
                "See for yourself", "Sign up free", "Take action", "This won’t last", "Urgent", "What are you waiting for?",
                "While supplies last", "Will not believe your eyes", "Winner", "Winning", "You are a winner", "You have been selected",

            )
        ),

        'Spammy' : (
            'shady, spammy, or unethical behavior',
            (
                "Bulk email", "Buy direct", "Cancel at any time", "Check or money order", "Congratulations", "Confidentiality",
                "Cures", "Dear friend", "Direct email", "Direct marketing", "Hidden charges", "Human growth hormone", "Internet marketing",
                "Lose weight", "Mass email", "Meet singles", "Multi-level marketing", "No catch", "No cost", "No credit check",
                "No fees", "No gimmick", "No hidden costs", "No hidden fees", "No interest", "No investment", "No obligation",
                "No purchase necessary", "No questions asked", "No strings attached", "Not junk", "Notspam", "Obligation",
                "Passwords", "Requires initial investment", "Social security number", "This isn’t a scam", "This isn’t junk", 
                "This isn’t spam", "Undisclosed", "Unsecured credit", "Unsecured debt", "Unsolicited", "Valium",
                "Viagra", "Vicodin", "We hate spam", "Weight loss", "Xanax",
            )
        ),

        'Jargon' : (
            'jargon or legalese',
            (
                "Accept credit cards", "All new", "As seen on", "Bargain", "Beneficiary", "Billing", "Bonus",
                "Cards accepted", "Cash", "Certified", "Cheap", "Claims", "Clearance", "Compare rates", "Credit card offers", 
                "Deal", "Debt", "Discount", "Fantastic", "In accordance with laws", "Income", "Investment", "Join millions",
                "Lifetime", "Loans", "Luxury", "Marketing solution", "Message contains", "Mortgage rates", "Name brand",
                "Offer", "Online marketing", "Opt in", "Pre-approved", "Quote", "Rates", "Refinance", "Removal", "Reserves the right",
                "Search engine", "Sent in compliance", "Subject to", "Terms and conditions", "Trial", "Unlimited",
                "Warranty", "Web traffic", "Work from home", 
            )
        ),
        
        'Shady' : (
            'ethically or legally questionable behavior',
            (
                "Addresses", "Beneficiary", "Billing", "Casino", "Celebrity", "Collect child support", "Copy DVDs", 
                "Fast viagra delivery", "Hidden", "Human growth hormone", "In accordance with laws", "Investment",
                "Junk", "Legal", "Life insurance", "Loan", "Lottery", "Luxury car", "Medicine", "Meet singles", "Message contains",
                "Miracle", "Money", "Multi-level marketing", "Nigerian", "Offshore", "Online degree", "Online pharmacy", "Passwords",
                "Refinance", "Request", "Rolex", "Social security number", "Spam", "This isn't spam", "Undisclosed recipient",
                "University diplomas", "Unsecured credit", "Unsolicited", "US dollars", "Valium", "Viagra", "Vicodin",
                "Warranty", "Xanax"
            )
        ),

        "Commerce" : (
            "",
            (
                "As seen on", "Buy", "Buy direct", "Buying judgments", "Clearance", "Order", "Order status", "Orders shipped by shopper",
            )
        ),

        "Personal" : (
            "",
            (
                "Dig up dirt on friends", "Meet singles", "Score with babes", "XXX", "Near you",
            )
        ),

        "Employment" : (
            "",
            (
                "Additional income", "Be your own boss", "Compete for your business", "Double your", "Earn $", "Earn extra cash",
                "Earn per week", "Expect to earn", "Extra income", "Home based", "Home employment", "Homebased business", "Income from home",
                "Make $", "Make money", "Money making", "Online biz opportunity", "Online degree", "Opportunity",
                "Potential earnings", "University diplomas", "While you sleep", "Work at home", "Work from home",
            )
        ),

        "Financial - General" : (
            "",
            (
                "$$$", "Affordable", "Bargain", "Beneficiary", "Best price", "Big bucks", "Cash", "Cash bonus", "Cashcashcash",
                "Cents on the dollar", "Cheap", "Check", "Claims", "Collect", "Compare rates", "Cost", "Credit", "Credit bureaus",
                "Discount", "Earn", "Easy terms", "F r e e", "Fast cash", "For just $XXX", "Hidden assets", "hidden charges",
                "Income", "Incredible deal", "Insurance", "Investment", "Loans", "Lowest price", "Million dollars", "Money",
                "Money back", "Mortgage", "Mortgage rates", "No cost", "No fees", "One hundred percent free", "Only $", "Pennies a day",
                "Price", "Profits", "Pure profit", "Quote", "Refinance", "Save $", "Save big money", "Save up to", "Serious cash",
                "Subject to credit", "They keep your money — no refund!", "Unsecured credit", "Unsecured debt",
                "US dollars", "Why pay more?",
            )
        ),

        "Financial - Business" : (
            "",
            (
                "Accept credit cards", "Cards accepted", "Check or money order", "Credit card offers", "Explode your business",
                "Full refund", "Investment decision", "No credit check", "No hidden Costs", "No investment",
                "Requires initial investment", "Sent in compliance", "Stock alert", "Stock disclaimer statement", "Stock pick",
            )
        ),

        "Financial - Personal" : (
            "",
            (
                "Avoice bankruptcy", "Calling creditors", "Collect child support", "Consolidate debt and credit", 
                "Consolidate your debt", "Eliminate bad credit", "Eliminate debt", "Financially independent",
                "Get out of debt", "Get paid", "Lower interest rate", "Lower monthly payment", "Lower your mortgage rate",
                "Lowest insurance rates", "Pre-approved", "Refinance home", "Social security number", "Your income",
            )
        ),

        "General" : (
            "",
            (
                "Acceptance", "Accordingly", "Avoid", "Chance", "Dormant", "Freedom", "Here", "Hidden", "Home", "Leave",
                "Lifetime", "Lose", "Maintained", "Medium", "Miracle", "Never", "Passwords", "Problem", "Remove", "Reverses",
                "Sample", "Satisfaction", "Solution", "Stop", "Success", "Teen", "Wife",
            )
        ),

        "Greetings" : (
            "",
            (
                "Dear ", "Friend", "Hello",
            )
        ),

        "Marketing" : (
            "",
            (
                "Ad", "Auto email removal", "Bulk email", "Click", "Click below", "Click here", "Click to remove", "Direct email",
                "Direct marketing", "Email harvest", "Email marketing", "Form", "Increase sales", "Increase traffic",
                "Increase your sales", "Internet market", "Internet marketing", "Marketing", "Marketing solutions", "Mass email",
                "Member", "Month trial offer", "More Internet Traffic", "Multi level marketing", "Notspam", "One time mailing",
                "Online marketing", "Open", "Opt in", "Performance", "Removal instructions", "Sale", "Sales",
                "Search engine listings", "Search engines", "Subscribe", "The following form", "This isn't junk", "This isn't spam",
                "Undisclosed recipient", "Unsubscribe", "Visit our website", "We hate spam", "Web traffic", "Will not believe your eyes",
            )
        ),

        "Medical" : (
            "",
            (
                "Cures baldness", "Diagnostic", "Fast Viagra delivery", "Human growth hormone", "Life insurance",
                "Lose weight", "Lose weight spam", "Medicine", "No medical exams", "Online pharmacy", "Removes wrinkles",
                "Reverses aging", "Stop snoring", "Valium", "Viagra", "Vicodin", "Weight loss", "Xanax", 
            )
        ),

        "Numbers" : (
            "",
            (
                "#1", "100% free", "100% satisfied", "4U", "50% off", "Billion", "Billion dollars", "Join millions", 
                "Join millions of Americans", "Million", "One hundred percent guaranteed", "Thousands",
            )
        ),

        "Offers" : (
            "",
            (
                "Being a member", "Billing address", "Call", "Cannot be combined with any other offer", 
                "Confidentially on all orders", "Deal", "Financial freedom", "Gift certificate", "Giving away",
                "Guarantee", "Have you been turned down?", "If only it were that easy", "Important information regarding", 
                "In accordance with laws", "Long distance phone offer", "Mail in order form", "Message contains",
                "Name brand", "Nigerian", "No age restrictions", "No catch", "No claim forms", "No disappointment",
                "No experience", "No gimmick", "No inventory", "No middleman", "No obligation", "No purchase necessary", 
                "No questions asked", "No selling", "No strings attached", "No-obligation", "Not intended",
                "Obligation", "Off shore", "Offer", "Per day", "Per week", "Priority mail", "Prize", "Prizes", 
                "Produced and sent out", "Reserves the right", "Shopping spree", "Stuff on sale", "Terms and conditions",
                "The best rates", "They’re just giving it away", "Trial", "Unlimited", "Unsolicited", "Vacation",
                "Vacation offers", "Warranty", "We honor all", "Weekend getaway", "What are you waiting for?", "Who really wins?",
                "Win", "Winner", "Winning", "Won", "You are a winner!", "You have been selected", "You’re a Winner!",
            )
        ),

        "Calls-to-Action" : (
            "",
            (
                "Cancel at any time", "Compare", "Copy accurately", "Get", "Give it away", "Print form signature", 
                "Print out and fax", "See for yourself", "Sign up free today",
            )
        ),

        "Free" : (
            "",
            (
                "Free", "Free access", "Free cell phone", "Free consultation", "Free DVD", "Free gift", "Free grant money",
                "Free hosting", "Free installation", "Free Instant", "Free investment", "Free leads", "Free membership",
                "Free money", "Free offer", "Free preview", "Free priority mail", "Free quote", "Free sample",
                "Free trial", "Free website",
            )
        ),

        "Descriptions/Adjectives" : (
            "",
            (
                "All natural", "All new", "Amazing", "Certified", "Congratulations", "Drastically reduced", "Fantastic deal",
                "For free", "Guaranteed", "It’s effective", "Outstanding values", "Promise you", "Real thing",
                "Risk free", "Satisfaction guaranteed",
            )
        ),

        "Sense of Urgency" : (
            "",
            (
                "Access", "Act now!", "Apply now", "Apply online", "Call free", "Call now", "Can't live without", "Do it today",
                "Don't delete", "Don't hesitate", "For instant access", "For Only", "For you", "Get it now", "Get started now",
                "Great offer", "Info you requested", "Information you requested", "Instant", "Limited time", "New customers only",
                "Now", "Now only", "Offer expires", "Once in lifetime", "One time", "Only", "Order now", "Order today",
                "Please read", "Special promotion", "Supplies are limited", "Take action now", "Time limited", "Urgent",
                "While supplies last",
            )
        ),

        "Nouns" : (
            "",
            (
                "Addresses on CD", "Beverage", "Bonus", "Brand new pager", "Cable converter", "Casino", "Celebrity",
                "Copy DVDs", "Laser printer", "Legal", "Luxury car", "New domain extensions", "Phone", "Rolex", "Stainless steel"
            )
        )
    }

    #
    # Assorted list of most frequently occuring SMTP headers.
    #
    # Collected & manually filtered from corpora of 1700 emails with following one-liner:
    # 
    #   for file in * ; do cat $file | sed -r '/^\s*$/d'| sed -e '/^-\{2,\}[0-9a-ZA-Z_\-]\+/,$d' | grep ':' | grep '^[a-zA-Z]' | pcregrep -o1 '^([a-zA-Z0-9_-]+): ' ; done | sort | uniq -c | sort -n -r
    #
    Usual_SMTP_Headers = (
        'Accept-Language',
        'ARC-Authentication-Results',
        'ARC-Message-Signature',
        'ARC-Seal',
        'Authentication-Results',
        'authentication-results',
        'Auto-Submitted',
        'Content-Disposition',
        'Content-ID',
        'Content-Id',
        'Content-Language',
        'Content-Transfer-Encoding',
        'Content-Type',
        'Content-type',
        'Date',
        'date',
        'Delivered-To',
        'Disposition-Notification-To',
        'DKIM-Filter',
        'DKIM-Signature',
        'dlp-product',
        'dlp-reaction',
        'dlp-version',
        'DomainKey-Signature',
        'Feedback-ID',
        'Feedback-Id',
        'From',
        'Gmail-Client-Draft-ID',
        'Gmail-Client-Draft-Thread-ID',
        'Importance',
        'In-Reply-To',
        'IronPort-SDR',
        'last-modified',
        'List-ID',
        'List-Id',
        'List-Unsubscribe',
        'List-unsubscribe',
        'List-Unsubscribe-Post',
        'mail-from',
        'Message-ID',
        'Message-Id',
        'MIME-Version',
        'Mime-Version',
        'msip_labels',
        'Origin-messageId',
        'Precedence',
        'Received',
        'Received-SPF',
        'received-spf',
        'Recipient-Id',
        'References',
        'Reply-To',
        'Reply-to',
        'Require-Recipient-Valid-Since',
        'Return-Path',
        'Return-Receipt-To',
        'Sender',
        'Sent',
        'spamdiagnosticmetadata',
        'spamdiagnosticoutput',
        'Subject',
        'Thread-Index',
        'Thread-Topic',
        'To',
        'User-Agent',
        'X-Abuse',
        'X-Accounttype',
        'X-AntiAbuse',
        'X-Attachment',
        'X-AuditID',
        'X-Auto-Response-Suppress',
        'X-Binding',
        'X-Brightmail-Tracker',
        'X-Campaign',
        'X-campaignid',
        'X-CampaignID',
        'X-Charset',
        'X-cid',
        'X-CLIENT-HOSTNAME',
        'X-CLIENT-IP',
        'X-CMAE-Analysis',
        'X-CMAE-Score',
        'X-Complaints-To',
        'X-Cron-Env',
        'X-CSA-Complaints',
        'X-DCC--Metrics',
        'X-Delivery-Context',
        'X-elqPod',
        'X-elqSiteID',
        'X-EMAIL-ID',
        'X-Email-Rejection-Mode',
        'X-Entity-ID',
        'x-eopattributedmessage',
        'x-exchange-antispam-report-cfa-test',
        'x-exchange-antispam-report-test',
        'X-FE-Draft-Info',
        'X-FE-Policy-ID',
        'X-FEAS-Auth-User',
        'X-FEAS-Bypass-Scan-On-Auth',
        'X-Feedback-ID',
        'x-forefront-antispam-report',
        'x-forefront-prvs',
        'X-Forwarded-Message-Id',
        'X-Gm-Message-State',
        'X-Google-DKIM-Signature',
        'X-Google-Sender-Auth',
        'X-Google-Sender-Delegation',
        'X-Google-Smtp-Source',
        'X-HS-Cid',
        'x-incomingheadercount',
        'X-IronPort-AV',
        'X-JID',
        'x-ld-processed',
        'X-LinkedIn-Class',
        'X-LinkedIn-fbl',
        'X-LinkedIn-Id',
        'X-LinkedIn-Template',
        'X-Mailer',
        'X-Mailgun-Batch-Id',
        'X-Mailgun-Sending-Ip',
        'X-Mailgun-Sid',
        'X-Mailgun-Tag',
        'X-Mailgun-Track',
        'X-Mailgun-Track-Clicks',
        'X-Mailgun-Track-Opens',
        'X-Mailgun-Variables',
        'X-MAILTAGS',
        'X-Mandrill-User',
        'X-MC-Unique',
        'X-MC-User',
        'x-mcpf-jobid',
        'X-messageUUID',
        'x-microsoft-antispam',
        'x-microsoft-antispam-message-info',
        'x-microsoft-antispam-prvs',
        'x-microsoft-exchange-diagnostics',
        'X-Mimecast-Spam-Score',
        'X-MIMETrack',
        'x-ms-exchange-antispam-messagedata',
        'x-ms-exchange-antispam-messagedata-0',
        'x-ms-exchange-antispam-messagedata-1',
        'x-ms-exchange-antispam-messagedata-chunkcount',
        'x-ms-exchange-antispam-relay',
        'x-ms-exchange-antispam-srfa-diagnostics',
        'x-ms-exchange-calendar-series-instance-id',
        'X-MS-Exchange-CrossTenant-AuthAs',
        'X-MS-Exchange-CrossTenant-AuthSource',
        'X-MS-Exchange-CrossTenant-fromentityheader',
        'X-MS-Exchange-CrossTenant-id',
        'X-MS-Exchange-CrossTenant-mailboxtype',
        'X-MS-Exchange-CrossTenant-Network-Message-Id',
        'X-MS-Exchange-CrossTenant-originalarrivaltime',
        'X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg',
        'X-MS-Exchange-CrossTenant-rms-persistedconsumerorg',
        'X-MS-Exchange-CrossTenant-userprincipalname',
        'x-ms-exchange-generated-message-source',
        'X-MS-Exchange-Inbox-Rules-Loop',
        'x-ms-exchange-meetingforward-message',
        'x-ms-exchange-messagesentrepresentingtype',
        'x-ms-exchange-parent-message-id',
        'x-ms-exchange-purlcount',
        'x-ms-exchange-senderadcheck',
        'X-MS-Exchange-Transport-CrossTenantHeadersStamped',
        'x-ms-exchange-transport-forked',
        'x-ms-exchange-transport-fromentityheader',
        'X-MS-Has-Attach',
        'x-ms-office365-filtering-correlation-id',
        'x-ms-office365-filtering-ht',
        'x-ms-oob-tlc-oobclassifiers',
        'x-ms-publictraffictype',
        'X-MS-TNEF-Correlator',
        'x-ms-traffictypediagnostic',
        'X-MSFBL',
        'X-OriginalArrivalTime',
        'X-Originating-Client',
        'x-originating-ip',
        'X-OriginatorOrg',
        'X-Ovh-Tracer-Id',
        'X-Priority',
        'X-Provags-ID',
        'X-Received',
        'X-Report-Abuse',
        'X-Report-Abuse-To',
        'X-REPORT-ABUSE-TO',
        'X-Return-Path',
        'X-Sender',
        'X-SES-Outgoing',
        'X-SG-EID',
        'X-SG-ID',
        'X-sib-id',
        'X-Sid',
        'X-Spam-Checker-Version',
        'X-Spam-Level',
        'X-Spam-Status',
        'X-Thread-Info',
        'X-TM-Deliver-Signature',
        'X-TM-MAIL-RECEIVED-TIME',
        'X-TM-MAIL-UUID',
        'x-tm-snts-smtp',
        'X-TM-SNTS-SMTP',
        'X-UI-Message-Type',
        'X-UI-Out-Filterresults',
        'X-VADE-SPAMCAUSE',
        'X-VADE-SPAMSTATE',
        'X-Virus-Scanned',
        'X-VR-SPAMCAUSE',
        'X-VR-SPAMSCORE',
        'X-VR-SPAMSTATE',
        'X-Zoho-RID',
        'X-Zoho-Virus-Status',
    )

    Time_Zone_Acronyms = (
        'A', 'ACDT', 'ACST', 'ACT', 'ACT', 'ACWST', 'ADST', 'ADST', 'ADT', 'ADT', 'AEDT', 'AEST', 'AET', 'AET', 'AFT', 'AKDT', 'AKST',
        'ALMT', 'AMDT', 'AMST', 'AMST', 'AMT', 'AMT', 'ANAST', 'ANAT', 'AoE', 'AQTT', 'ART', 'AST', 'AST', 'AST', 'AST', 'AST', 'AST',
        'AST', 'AT', 'AT', 'AT', 'AWDT', 'AWST', 'AZODT', 'AZOST', 'AZOST', 'AZOT', 'AZST', 'AZT', 'B', 'BDST', 'BDT', 'BDT', 'BNT',
        'BOT', 'BRST', 'BRT', 'BST', 'BST', 'BST', 'BST', 'BST', 'BT', 'BT', 'BTT', 'C', 'CAST', 'CAT', 'CCT', 'CDST', 'CDST', 'CDT',
        'CDT', 'CDT', 'CDT', 'CEDT', 'CEST', 'CET', 'CET', 'CHADT', 'CHAST', 'CHODST', 'CHODT', 'CHOST', 'CHOT', 'ChST', 'CHUT', 
        'CIDST', 'CIST', 'CIT', 'CKT', 'CLDT', 'CLST', 'CLST', 'CLT', 'COT', 'CST', 'CST', 'CST', 'CST', 'CST', 'CT', 'CT', 'CT',
        'CVT', 'CXT', 'D', 'DAVT', 'DDUT', 'E', 'EADT', 'EASST', 'EAST', 'EAT', 'EAT', 'ECST', 'ECT', 'ECT', 'EDST', 'EDST', 'EDT',
        'EDT', 'EDT', 'EEDT', 'EEST', 'EET', 'EFATE', 'EGST', 'EGST', 'EGT', 'EGT', 'EST', 'EST', 'ET', 'ET', 'ET', 'F', 'FET', 
        'FJDT', 'FJST', 'FJT', 'FKDT', 'FKST', 'FKST', 'FKT', 'FNT', 'G', 'GALT', 'GAMT', 'GAMT', 'GET', 'GFT', 'GILT', 'GMT', 
        'GMT', 'GST', 'GST', 'GST', 'GT', 'GYT', 'H', 'HAA', 'HAC', 'HADT', 'HAE', 'HAP', 'HAR', 'HAST', 'HAT', 'HDT', 'HKT', 
        'HLV', 'HNA', 'HNC', 'HNE', 'HNP', 'HNR', 'HNT', 'HOVDST', 'HOVDT', 'HOVST', 'HOVT', 'HST', 'I', 'ICT', 'IDT', 'IDT', 
        'Indian', 'IOT', 'IRDT', 'IRKST', 'IRKT', 'IRST', 'IRST', 'IST', 'IST', 'IST', 'IST', 'IST', 'IT', 'IT', 'JST', 'K', 'KGT',
        'KIT', 'KOST', 'KRAST', 'KRAT', 'KST', 'KST', 'KT', 'KUYT', 'L', 'LHDT', 'LHST', 'LINT', 'M', 'MAGST', 'MAGST', 'MAGT', 
        'MAGT', 'MART', 'MAWT', 'MCK', 'MDST', 'MDT', 'MESZ', 'MEZ', 'MHT', 'MMT', 'Moscow', 'MSD', 'MSK', 'MST', 'MST', 'MT', 
        'MT', 'MUT', 'MVT', 'MYT', 'N', 'NACDT', 'NACST', 'NAEDT', 'NAEST', 'NAMDT', 'NAMST', 'NAPDT', 'NAPST', 'NCT', 'NDT', 'NFDT',
        'NFDT', 'NFT', 'NFT', 'NOVST', 'NOVST', 'NOVT', 'NOVT', 'NPT', 'NRT', 'NST', 'NUT', 'NZDT', 'NZST', 'O', 'OESZ', 'OEZ', 
        'OMSST', 'OMSST', 'OMST', 'OMST', 'OMST', 'ORAT', 'P', 'Pacifi', 'PDST', 'PDT', 'PET', 'PETST', 'PETT', 'PETT', 'PGT', 
        'PHOT', 'PHT', 'PKT', 'PKT', 'PMDT', 'PMST', 'PONT', 'PST', 'PST', 'PST', 'PT', 'PT', 'PT', 'PWT', 'PYST', 'PYST', 'PYT', 
        'PYT', 'Q', 'QYZT', 'R', 'RET', 'ROTT', 'S', 'SAKT', 'SAMST', 'SAMT', 'SAMT', 'SAST', 'SAST', 'SBT', 'SBT', 'SCT', 'SGT', 
        'SRET', 'SRT', 'SST', 'SST', 'ST', 'SYOT', 'T', 'TAHT', 'TFT', 'TJT', 'TKT', 'TLT', 'TMT', 'TOST', 'TOT', 'TRT', 'TVT', 
        'U', 'ULAST', 'ULAST', 'ULAT', 'ULAT', 'UTC', 'UYST', 'UYT', 'UZT', 'V', 'VET', 'VLAST', 'VLAT', 'VOST', 'VUT', 'W', 
        'WAKT', 'WARST', 'WAST', 'WAT', 'WAT', 'WDT', 'WEDT', 'WEST', 'WESZ', 'WET', 'WEZ', 'WFT', 'WGST', 'WGST', 'WGT', 'WGT',
        'WIB', 'WIB', 'WIT', 'WIT', 'WITA', 'WITA', 'WST', 'WST', 'WST', 'WST', 'WT', 'WT', 'X', 'Y', 'YAKST', 'YAKT', 'YAPT',
        'YEKST', 'YEKT', 'Z',
    )

    # https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
    Exchange_Versions = (
        Verstring('Exchange Server 4.0 SP5 ', 'May 5, 1998', '4.0.996'),
        Verstring('Exchange Server 4.0 SP4 ', 'March 28, 1997', '4.0.995'),
        Verstring('Exchange Server 4.0 SP3 ', 'October 29, 1996', '4.0.994'),
        Verstring('Exchange Server 4.0 SP2 ', 'July 19, 1996', '4.0.993'),
        Verstring('Exchange Server 4.0 SP1 ', 'May 1, 1996', '4.0.838'),
        Verstring('Exchange Server 4.0 Standard Edition', 'June 11, 1996', '4.0.837'),
        Verstring('Exchange Server 5.0 SP2 ', 'February 19, 1998', '5.0.1460'),
        Verstring('Exchange Server 5.0 SP1 ', 'June 18, 1997', '5.0.1458'),
        Verstring('Exchange Server 5.0 ', 'May 23, 1997', '5.0.1457'),
        Verstring('Exchange Server version 5.5 SP4 ', 'November 1, 2000', '5.5.2653'),
        Verstring('Exchange Server version 5.5 SP3 ', 'September 9, 1999', '5.5.2650'),
        Verstring('Exchange Server version 5.5 SP2 ', 'December 23, 1998', '5.5.2448'),
        Verstring('Exchange Server version 5.5 SP1 ', 'August 5, 1998', '5.5.2232'),
        Verstring('Exchange Server version 5.5 ', 'February 3, 1998', '5.5.1960'),
        Verstring('Exchange 2000 Server post-SP3', 'August 2008', '6.0.6620.7'),
        Verstring('Exchange 2000 Server post-SP3', 'March 2008', '6.0.6620.5'),
        Verstring('Exchange 2000 Server post-SP3', 'August 2004', '6.0.6603'),
        Verstring('Exchange 2000 Server post-SP3', 'April 2004', '6.0.6556'),
        Verstring('Exchange 2000 Server post-SP3', 'September 2003', '6.0.6487'),
        Verstring('Exchange 2000 Server SP3', 'July 18, 2002', '6.0.6249'),
        Verstring('Exchange 2000 Server SP2', 'November 29, 2001', '6.0.5762'),
        Verstring('Exchange 2000 Server SP1', 'June 21, 2001', '6.0.4712'),
        Verstring('Exchange 2000 Server', 'November 29, 2000', '6.0.4417'),
        Verstring('Exchange Server 2003 post-SP2', 'August 2008', '6.5.7654.4'),
        Verstring('Exchange Server 2003 post-SP2', 'March 2008', '6.5.7653.33'),
        Verstring('Exchange Server 2003 SP2', 'October 19, 2005', '6.5.7683'),
        Verstring('Exchange Server 2003 SP1', 'May25, 2004', '6.5.7226'),
        Verstring('Exchange Server 2003', 'September 28, 2003', '6.5.6944'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP2', 'December 7, 2010', '8.2.305.3', '8.02.0305.003'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP2', 'April 9, 2010', '8.2.254.0', '8.02.0254.000'),
        Verstring('Update Rollup 3 for Exchange Server 2007 SP2', 'March 17, 2010', '8.2.247.2', '8.02.0247.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP2', 'January 22, 2010', '8.2.234.1', '8.02.0234.001'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP2', 'November 19, 2009', '8.2.217.3', '8.02.0217.003'),
        Verstring('Exchange Server 2007 SP2', 'August 24, 2009', '8.2.176.2', '8.02.0176.002'),
        Verstring('Update Rollup 10 for Exchange Server 2007 SP1', 'April 13, 2010', '8.1.436.0', '8.01.0436.000'),
        Verstring('Update Rollup 9 for Exchange Server 2007 SP1', 'July 16, 2009', '8.1.393.1', '8.01.0393.001'),
        Verstring('Update Rollup 8 for Exchange Server 2007 SP1', 'May 19, 2009', '8.1.375.2', '8.01.0375.002'),
        Verstring('Update Rollup 7 for Exchange Server 2007 SP1', 'March 18, 2009', '8.1.359.2', '8.01.0359.002'),
        Verstring('Update Rollup 6 for Exchange Server 2007 SP1', 'February 10, 2009', '8.1.340.1', '8.01.0340.001'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP1', 'November 20, 2008', '8.1.336.1', '8.01.0336.01'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP1', 'October 7, 2008', '8.1.311.3', '8.01.0311.003'),
        Verstring('Update Rollup 3 for Exchange Server 2007 SP1', 'July 8, 2008', '8.1.291.2', '8.01.0291.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP1', 'May 9, 2008', '8.1.278.2', '8.01.0278.002'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP1', 'February 28, 2008', '8.1.263.1', '8.01.0263.001'),
        Verstring('Exchange Server 2007 SP1', 'November 29, 2007', '8.1.240.6', '8.01.0240.006'),
        Verstring('Update Rollup 7 for Exchange Server 2007', 'July 8, 2008', '8.0.813.0', '8.00.0813.000'),
        Verstring('Update Rollup 6 for Exchange Server 2007', 'February 21, 2008', '8.0.783.2', '8.00.0783.002'),
        Verstring('Update Rollup 5 for Exchange Server 2007', 'October 25, 2007', '8.0.754.0', '8.00.0754.000'),
        Verstring('Update Rollup 4 for Exchange Server 2007', 'August 23, 2007', '8.0.744.0', '8.00.0744.000'),
        Verstring('Update Rollup 3 for Exchange Server 2007', 'June 28, 2007', '8.0.730.1', '8.00.0730.001'),
        Verstring('Update Rollup 2 for Exchange Server 2007', 'May 8, 2007', '8.0.711.2', '8.00.0711.002'),
        Verstring('Update Rollup 1 for Exchange Server 2007', 'April 17, 2007', '8.0.708.3', '8.00.0708.003'),
        Verstring('Exchange Server 2007 RTM', 'March 8, 2007', '8.0.685.25  8.00.0685.025'),
        Verstring('Update Rollup 23 for Exchange Server 2007 SP3', 'March 21, 2017', '8.3.517.0', '8.03.0517.000'),
        Verstring('Update Rollup 22 for Exchange Server 2007 SP3', 'December 13, 2016', '8.3.502.0', '8.03.0502.000'),
        Verstring('Update Rollup 21 for Exchange Server 2007 SP3', 'September 20, 2016', '8.3.485.1', '8.03.0485.001'),
        Verstring('Update Rollup 20 for Exchange Server 2007 SP3', 'June 21, 2016', '8.3.468.0', '8.03.0468.000'),
        Verstring('Update Rollup 19 forExchange Server 2007 SP3', 'March 15, 2016', '8.3.459.0', '8.03.0459.000'),
        Verstring('Update Rollup 18 forExchange Server 2007 SP3', 'December, 2015', '8.3.445.0', '8.03.0445.000'),
        Verstring('Update Rollup 17 forExchange Server 2007 SP3', 'June 17, 2015', '8.3.417.1', '8.03.0417.001'),
        Verstring('Update Rollup 16 for Exchange Server 2007 SP3', 'March 17, 2015', '8.3.406.0', '8.03.0406.000'),
        Verstring('Update Rollup 15 for Exchange Server 2007 SP3', 'December 9, 2014', '8.3.389.2', '8.03.0389.002'),
        Verstring('Update Rollup 14 for Exchange Server 2007 SP3', 'August 26, 2014', '8.3.379.2', '8.03.0379.002'),
        Verstring('Update Rollup 13 for Exchange Server 2007 SP3', 'February 24, 2014', '8.3.348.2', '8.03.0348.002'),
        Verstring('Update Rollup 12 for Exchange Server 2007 SP3', 'December 9, 2013', '8.3.342.4', '8.03.0342.004'),
        Verstring('Update Rollup 11 for Exchange Server 2007 SP3', 'August 13, 2013', '8.3.327.1', '8.03.0327.001'),
        Verstring('Update Rollup 10 for Exchange Server 2007 SP3', 'February 11, 2013', '8.3.298.3', '8.03.0298.003'),
        Verstring('Update Rollup 9 for Exchange Server 2007 SP3', 'December 10, 2012', '8.3.297.2', '8.03.0297.002'),
        Verstring('Update Rollup 8-v3 for Exchange Server 2007 SP3 ', 'November 13, 2012', '8.3.279.6', '8.03.0279.006'),
        Verstring('Update Rollup 8-v2 for Exchange Server 2007 SP3 ', 'October 9, 2012', '8.3.279.5', '8.03.0279.005'),
        Verstring('Update Rollup 8 for Exchange Server 2007 SP3', 'August 13, 2012', '8.3.279.3', '8.03.0279.003'),
        Verstring('Update Rollup 7 for Exchange Server 2007 SP3', 'April 16, 2012', '8.3.264.0', '8.03.0264.000'),
        Verstring('Update Rollup 6 for Exchange Server 2007 SP3', 'January 26, 2012', '8.3.245.2', '8.03.0245.002'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP3', 'September 21, 2011', '8.3.213.1', '8.03.0213.001'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP3', 'May 28, 2011', '8.3.192.1', '8.03.0192.001'),
        Verstring('Update Rollup 3-v2 for Exchange Server 2007 SP3 ', 'March 30, 2011', '8.3.159.2', '8.03.0159.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP3', 'December 10, 2010', '8.3.137.3', '8.03.0137.003'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP3', 'September 9, 2010', '8.3.106.2', '8.03.0106.002'),
        Verstring('Exchange Server 2007 SP3', 'June 7, 2010', '8.3.83.6', '8.03.0083.006'),
        Verstring('Update Rollup 8 for Exchange Server 2010 SP2', 'December 9, 2013', '14.2.390.3  14.02.0390.003'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP2', 'August 3, 2013', '14.2.375.0  14.02.0375.000'),
        Verstring('Update Rollup 6 Exchange Server 2010 SP2', 'February 12, 2013', '14.2.342.3  14.02.0342.003'),
        Verstring('Update Rollup 5 v2 for Exchange Server 2010 SP2 ', 'December 10, 2012', '14.2.328.10 14.02.0328.010'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP2', 'November 13, 2012', '14.3.328.5  14.03.0328.005'),
        Verstring('Update Rollup 4 v2 for Exchange Server 2010 SP2 ', 'October 9, 2012', '14.2.318.4  14.02.0318.004'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP2', 'August 13, 2012', '14.2.318.2  14.02.0318.002'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP2', 'May 29, 2012', '14.2.309.2  14.02.0309.002'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP2', 'April 16, 2012', '14.2.298.4  14.02.0298.004'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP2', 'February 13, 2012', '14.2.283.3  14.02.0283.003'),
        Verstring('Exchange Server 2010 SP2', 'December 4, 2011', '14.2.247.5  14.02.0247.005'),
        Verstring('Update Rollup 8 for Exchange Server 2010 SP1', 'December 10, 2012', '14.1.438.0  14.01.0438.000'),
        Verstring('Update Rollup 7 v3 for Exchange Server 2010 SP1 ', 'November 13, 2012', '14.1.421.3  14.01.0421.003'),
        Verstring('Update Rollup 7 v2 for Exchange Server 2010 SP1 ', 'October 10, 2012', '14.1.421.2  14.01.0421.002'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP1', 'August 8, 2012', '14.1.421.0  14.01.0421.000'),
        Verstring('Update Rollup 6 for Exchange Server 2010 SP1', 'October 27, 2011', '14.1.355.2  14.01.0355.002'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP1', 'August 23, 2011', '14.1.339.1  14.01.0339.001'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP1', 'July 27, 2011', '14.1.323.6  14.01.0323.006'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP1', 'April 6, 2011', '14.1.289.7  14.01.0289.007'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP1', 'December 9, 2010', '14.1.270.1  14.01.0270.001'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP1', 'October 4, 2010', '14.1.255.2  14.01.0255.002'),
        Verstring('Exchange Server 2010 SP1', 'August 23, 2010', '14.1.218.15 14.01.0218.015'),
        Verstring('Update Rollup 5 for Exchange Server 2010', 'December 13, 2010', '14.0.726.0  14.00.0726.000'),
        Verstring('Update Rollup 4 for Exchange Server 2010', 'June 10, 2010', '14.0.702.1  14.00.0702.001'),
        Verstring('Update Rollup 3 for Exchange Server 2010', 'April 13, 2010', '14.0.694.0  14.00.0694.000'),
        Verstring('Update Rollup 2 for Exchange Server 2010', 'March 4, 2010', '14.0.689.0  14.00.0689.000'),
        Verstring('Update Rollup 1 for Exchange Server 2010', 'December 9, 2009', '14.0.682.1  14.00.0682.001'),
        Verstring('Exchange Server 2010 RTM', 'November 9, 2009', '14.0.639.21 14.00.0639.021'),
        Verstring('Update Rollup 29 for Exchange Server 2010 SP3', 'July 9, 2019', '14.3.468.0  14.03.0468.000'),
        Verstring('Update Rollup 28 for Exchange Server 2010 SP3', 'June 7, 2019', '14.3.461.1  14.03.0461.001'),
        Verstring('Update Rollup 27 for Exchange Server 2010 SP3', 'April 9, 2019', '14.3.452.0  14.03.0452.000'),
        Verstring('Update Rollup 26 for Exchange Server 2010 SP3', 'February 12, 2019', '14.3.442.0  14.03.0442.000'),
        Verstring('Update Rollup 25 for Exchange Server 2010 SP3', 'January 8, 2019', '14.3.435.0  14.03.0435.000'),
        Verstring('Update Rollup 24 for Exchange Server 2010 SP3', 'September 5, 2018', '14.3.419.0  14.03.0419.000'),
        Verstring('Update Rollup 23 for Exchange Server 2010 SP3', 'August 13, 2018', '14.3.417.1  14.03.0417.001'),
        Verstring('Update Rollup 22 for Exchange Server 2010 SP3', 'June 19, 2018', '14.3.411.0  14.03.0411.000'),
        Verstring('Update Rollup 21 for Exchange Server 2010 SP3', 'May 7, 2018', '14.3.399.2  14.03.0399.002'),
        Verstring('Update Rollup 20 for Exchange Server 2010 SP3', 'March 5, 2018', '14.3.389.1  14.03.0389.001'),
        Verstring('Update Rollup 19 for Exchange Server 2010 SP3', 'December 19, 2017', '14.3.382.0  14.03.0382.000'),
        Verstring('Update Rollup 18 for Exchange Server 2010 SP3', 'July 11, 2017', '14.3.361.1  14.03.0361.001'),
        Verstring('Update Rollup 17 for Exchange Server 2010 SP3', 'March 21, 2017', '14.3.352.0  14.03.0352.000'),
        Verstring('Update Rollup 16 for Exchange Server 2010 SP3', 'December 13, 2016', '14.3.336.0  14.03.0336.000'),
        Verstring('Update Rollup 15 for Exchange Server 2010 SP3', 'September 20, 2016', '14.3.319.2  14.03.0319.002'),
        Verstring('Update Rollup 14 for Exchange Server 2010 SP3', 'June 21, 2016', '14.3.301.0  14.03.0301.000'),
        Verstring('Update Rollup 13 for Exchange Server 2010 SP3', 'March 15, 2016', '14.3.294.0  14.03.0294.000'),
        Verstring('Update Rollup 12 for Exchange Server 2010 SP3', 'December 15, 2015', '14.3.279.2  14.03.0279.002'),
        Verstring('Update Rollup 11 for Exchange Server 2010 SP3', 'September 15, 2015', '14.3.266.2  14.03.0266.002'),
        Verstring('Update Rollup 10 for Exchange Server 2010 SP3', 'June 17, 2015', '14.3.248.2  14.03.0248.002'),
        Verstring('Update Rollup 9 for Exchange Server 2010 SP3', 'March 17, 2015', '14.3.235.1  14.03.0235.001'),
        Verstring('Update Rollup 8 v2 for Exchange Server 2010 SP3 ', 'December 12, 2014', '14.3.224.2  14.03.0224.002'),
        Verstring('Update Rollup 8 v1 for Exchange Server 2010 SP3 (recalled)  ', 'December 9, 2014', '14.3.224.1  14.03.0224.001'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP3', 'August 26, 2014', '14.3.210.2  14.03.0210.002'),
        Verstring('Update Rollup 6 for Exchange Server 2010 SP3', 'May 27, 2014', '14.3.195.1  14.03.0195.001'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP3', 'February 24, 2014', '14.3.181.6  14.03.0181.006'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP3', 'December 9, 2013', '14.3.174.1  14.03.0174.001'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP3', 'November 25, 2013', '14.3.169.1  14.03.0169.001'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP3', 'August 8, 2013', '14.3.158.1  14.03.0158.001'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP3', 'May 29, 2013', '14.3.146.0  14.03.0146.000'),
        Verstring('Exchange Server 2010 SP3', 'February 12, 2013', '14.3.123.4  14.03.0123.004'),
        Verstring('Exchange Server 2013 CU23', 'June 18, 2019', '15.0.1497.2 15.00.1497.002'),
        Verstring('Exchange Server 2013 CU22', 'February 12, 2019', '15.0.1473.3 15.00.1473.003'),
        Verstring('Exchange Server 2013 CU21', 'June 19, 2018', '15.0.1395.4 15.00.1395.004'),
        Verstring('Exchange Server 2013 CU20', 'March 20, 2018', '15.0.1367.3 15.00.1367.003'),
        Verstring('Exchange Server 2013 CU19', 'December 19, 2017', '15.0.1365.1 15.00.1365.001'),
        Verstring('Exchange Server 2013 CU18', 'September 19, 2017', '15.0.1347.2 15.00.1347.002'),
        Verstring('Exchange Server 2013 CU17', 'June 27, 2017', '15.0.1320.4 15.00.1320.004'),
        Verstring('Exchange Server 2013 CU16', 'March 21, 2017', '15.0.1293.2 15.00.1293.002'),
        Verstring('Exchange Server 2013 CU15', 'December 13, 2016', '15.0.1263.5 15.00.1263.005'),
        Verstring('Exchange Server 2013 CU14', 'September 20, 2016', '15.0.1236.3 15.00.1236.003'),
        Verstring('Exchange Server 2013 CU13', 'June 21, 2016', '15.0.1210.3 15.00.1210.003'),
        Verstring('Exchange Server 2013 CU12', 'March 15, 2016', '15.0.1178.4 15.00.1178.004'),
        Verstring('Exchange Server 2013 CU11', 'December 15, 2015', '15.0.1156.6 15.00.1156.006'),
        Verstring('Exchange Server 2013 CU10', 'September 15, 2015', '15.0.1130.7 15.00.1130.007'),
        Verstring('Exchange Server 2013 CU9', 'June 17, 2015', '15.0.1104.5 15.00.1104.005'),
        Verstring('Exchange Server 2013 CU8', 'March 17, 2015', '15.0.1076.9 15.00.1076.009'),
        Verstring('Exchange Server 2013 CU7', 'December 9, 2014', '15.0.1044.25', '15.00.1044.025'),
        Verstring('Exchange Server 2013 CU6', 'August 26, 2014', '15.0.995.29 15.00.0995.029'),
        Verstring('Exchange Server 2013 CU5', 'May 27, 2014', '15.0.913.22 15.00.0913.022'),
        Verstring('Exchange Server 2013 SP1', 'February 25, 2014', '15.0.847.32 15.00.0847.032'),
        Verstring('Exchange Server 2013 CU3', 'November 25, 2013', '15.0.775.38 15.00.0775.038'),
        Verstring('Exchange Server 2013 CU2', 'July 9, 2013', '15.0.712.24 15.00.0712.024'),
        Verstring('Exchange Server 2013 CU1', 'April 2, 2013', '15.0.620.29 15.00.0620.029'),
        Verstring('Exchange Server 2013 RTM', 'December 3, 2012', '15.0.516.32 15.00.0516.03'),
        Verstring('Exchange Server 2016 CU14', 'September 17, 2019', '15.1.1847.3 15.01.1847.003'),
        Verstring('Exchange Server 2016 CU13', 'June 18, 2019', '15.1.1779.2 15.01.1779.002'),
        Verstring('Exchange Server 2016 CU12', 'February 12, 2019', '15.1.1713.5 15.01.1713.005'),
        Verstring('Exchange Server 2016 CU11', 'October 16, 2018', '15.1.1591.10', '15.01.1591.010'),
        Verstring('Exchange Server 2016 CU10', 'June 19, 2018', '15.1.1531.3 15.01.1531.003'),
        Verstring('Exchange Server 2016 CU9', 'March 20, 2018', '15.1.1466.3 15.01.1466.003'),
        Verstring('Exchange Server 2016 CU8', 'December 19, 2017', '15.1.1415.2 15.01.1415.002'),
        Verstring('Exchange Server 2016 CU7', 'September 19, 2017', '15.1.1261.35', '15.01.1261.035'),
        Verstring('Exchange Server 2016 CU6', 'June 27, 2017', '15.1.1034.26', '15.01.1034.026'),
        Verstring('Exchange Server 2016 CU5', 'March 21, 2017', '15.1.845.34 15.01.0845.034'),
        Verstring('Exchange Server 2016 CU4', 'December 13, 2016', '15.1.669.32 15.01.0669.032'),
        Verstring('Exchange Server 2016 CU3', 'September 20, 2016', '15.1.544.27 15.01.0544.027'),
        Verstring('Exchange Server 2016 CU2', 'June 21, 2016', '15.1.466.34 15.01.0466.034'),
        Verstring('Exchange Server 2016 CU1', 'March 15, 2016', '15.1.396.30 15.01.0396.030'),
        Verstring('Exchange Server 2016 RTM', 'October 1, 2015', '15.1.225.42 15.01.0225.042'),
        Verstring('Exchange Server 2016 Preview', 'July 22, 2015', '15.1.225.16 15.01.0225.016'),
        Verstring('Exchange Server 2019 CU3', 'September 17, 2019', '15.2.464.5  15.02.0464.005'),
        Verstring('Exchange Server 2019 CU2', 'June 18, 2019', '15.2.397.3  15.02.0397.003'),
        Verstring('Exchange Server 2019 CU1', 'February 12, 2019', '15.2.330.5  15.02.0330.005'),
        Verstring('Exchange Server 2019 RTM', 'October 22, 2018', '15.2.221.12 15.02.0221.012'),
        Verstring('Exchange Server 2019 Preview', 'July 24, 2018', '15.2.196.0  15.02.0196.000'),
        Verstring('Exchange Server 2019 CU11', 'October 12, 2021', '15.2.986.9'),
        Verstring('Exchange Server 2019 CU11', 'September 28, 2021', '15.2.986.5'),
        Verstring('Exchange Server 2019 CU10', 'October 12, 2021', '15.2.922.14'),
        Verstring('Exchange Server 2019 CU10', 'July 13, 2021', '15.2.922.13'),
        Verstring('Exchange Server 2019 CU10', 'June 29, 2021', '15.2.922.7'),
        Verstring('Exchange Server 2019 CU9', 'July 13, 2021', '15.2.858.15'),
        Verstring('Exchange Server 2019 CU9', 'May 11, 2021', '15.2.858.12'),
        Verstring('Exchange Server 2019 CU9', 'April 13, 2021', '15.2.858.10'),
        Verstring('Exchange Server 2019 CU9', 'March 16, 2021', '15.2.858.5'),
        Verstring('Exchange Server 2019 CU8', 'May 11, 2021', '15.2.792.15'),
        Verstring('Exchange Server 2019 CU8', 'April 13, 2021', '15.2.792.13'),
        Verstring('Exchange Server 2019 CU8', 'March 2, 2021', '15.2.792.10'),
        Verstring('Exchange Server 2019 CU8', 'December 15, 2020', '15.2.792.3'),
        Verstring('Exchange Server 2019 CU7', 'March 2, 2021', '15.2.721.13'),
        Verstring('Exchange Server 2019 CU7', 'September 15, 2020', '15.2.721.2'),
        Verstring('Exchange Server 2019 CU6', 'March 2, 2021', '15.2.659.12'),
        Verstring('Exchange Server 2019 CU6', 'June 16, 2020', '15.2.659.4'),
        Verstring('Exchange Server 2019 CU5', 'March 2, 2021', '15.2.595.8'),
        Verstring('Exchange Server 2019 CU5', 'March 17, 2020', '15.2.595.3'),
        Verstring('Exchange Server 2019 CU4', 'March 2, 2021', '15.2.529.13'),
        Verstring('Exchange Server 2019 CU4', 'December 17, 2019', '15.2.529.5'),
        Verstring('Exchange Server 2019 CU3', 'March 2, 2021', '15.2.464.15'),
    )

    Manually_Added_Appliances = set()

    def __init__(self, logger, resolve = False, decode_all = False, testsToRun = [], includeUnusual = False):
        self.text = ''
        self.results = {}
        self.resolve = resolve
        self.decode_all = decode_all
        self.logger = logger
        self.received_path = []
        self.testsToRun = testsToRun
        self.securityAppliances = set()
        self.mtaHostnamesExposed = {}
        self.ipgeoCache = {}
        self.includeUnusual = includeUnusual

        # (number, header, value)
        self.headers = []

    def addSecurityAppliance(self, name):
        SMTPHeadersAnalysis.Manually_Added_Appliances.add(name.lower())
        self.securityAppliances.add(name)

    def getAllTests(self):

        tests = (
            ( '1', 'Received - Mail Servers Flow',                self.testReceived),
            ( '2', 'Extracted IP addresses',                      self.testExtractIP),
            ( '3', 'Extracted Domains',                           self.testResolveIntoIP),
            ( '4', 'Bad Keywords In Headers',                     self.testBadKeywords),
            ( '5', 'Sender Address Analysis',                     self.testFrom),
            ( '6', 'Subject and Thread Topic Difference',         self.testSubjecThreadTopic),
            ( '7', 'Authentication-Results',                      self.testAuthenticationResults),
            ( '8', 'ARC-Authentication-Results',                  self.testARCAuthenticationResults),
            ( '9', 'Received-SPF',                                self.testReceivedSPF),
            ('10', 'Mail Client Version',                         self.testXMailer),
            ('11', 'User-Agent Version',                          self.testUserAgent),
            ('12', 'X-Forefront-Antispam-Report',                 self.testForefrontAntiSpamReport),
            ('13', 'X-MS-Exchange-Organization-SCL',              self.testForefrontAntiSCL),
            ('14', 'X-Microsoft-Antispam-Mailbox-Delivery',       self.testAntispamMailboxDelivery),
            ('15', 'X-Microsoft-Antispam Bulk Mail',              self.testMicrosoftAntiSpam),
            ('16', 'X-Exchange-Antispam-Report-CFA-Test',         self.testAntispamReportCFA),
            ('17', 'Domain Impersonation',                        self.testDomainImpersonation),
            ('18', 'SpamAssassin Spam Status',                    self.testSpamAssassinSpamStatus),
            ('19', 'SpamAssassin Spam Level',                     self.testSpamAssassinSpamLevel),
            ('20', 'SpamAssassin Spam Flag',                      self.testSpamAssassinSpamFlag),
            ('21', 'SpamAssassin Spam Report',                    self.testSpamAssassinSpamReport),
            ('22', 'OVH\'s X-VR-SPAMCAUSE',                       self.testSpamCause),
            ('23', 'OVH\'s X-Ovh-Spam-Reason',                    self.testOvhSpamReason),
            ('24', 'OVH\'s X-Ovh-Spam-Score',                     self.testOvhSpamScore),
            ('25', 'X-Virus-Scan',                                self.testXVirusScan),
            ('26', 'X-Spam-Checker-Version',                      self.testXSpamCheckerVersion),
            ('27', 'X-IronPort-AV',                               self.testXIronPortAV),
            ('28', 'X-IronPort-Anti-Spam-Filtered',               self.testXIronPortSpamFiltered),
            ('29', 'X-IronPort-Anti-Spam-Result',                 self.testXIronPortSpamResult),
            ('30', 'X-Mimecast-Spam-Score',                       self.testXMimecastSpamScore),
            ('31', 'Spam Diagnostics Metadata',                   self.testSpamDiagnosticMetadata),
            ('32', 'MS Defender ATP Message Properties',          self.testATPMessageProperties),
            ('33', 'Message Feedback Loop',                       self.testMSFBL),
            ('34', 'End-to-End Latency - Message Delivery Time',  self.testTransportEndToEndLatency),
            #('35', 'X-MS-Oob-TLC-OOBClassifiers',                 self.testTLCOObClasifiers),
            ('36', 'X-IP-Spam-Verdict',                           self.testXIPSpamVerdict),
            ('37', 'X-Amp-Result',                                self.testXAmpResult),
            ('38', 'X-IronPort-RemoteIP',                         self.testXIronPortRemoteIP),
            ('39', 'X-IronPort-Reputation',                       self.testXIronPortReputation),
            ('40', 'X-SBRS',                                      self.testXSBRS),
            ('41', 'X-IronPort-SenderGroup',                      self.testXIronPortSenderGroup),
            ('42', 'X-Policy',                                    self.testXPolicy),
            ('43', 'X-IronPort-MailFlowPolicy',                   self.testXIronPortMailFlowPolicy),
            ('44', 'X-SEA-Spam',                                  self.testXSeaSpam),
            ('45', 'X-FireEye',                                   self.testXFireEye),
            ('46', 'X-AntiAbuse',                                 self.testXAntiAbuse),
            ('47', 'X-TMASE-Version',                             self.testXTMVersion),
            ('48', 'X-TM-AS-Product-Ver',                         self.testXTMProductVer),
            ('49', 'X-TM-AS-Result',                              self.testXTMResult),
            ('50', 'X-IMSS-Scan-Details',                         self.testXTMScanDetails),
            ('51', 'X-TM-AS-User-Approved-Sender',                self.testXTMApprSender),
            ('52', 'X-TM-AS-User-Blocked-Sender',                 self.testXTMBlockSender),
            ('53', 'X-TMASE-Result',                              self.testXTMASEResult),
            ('54', 'X-TMASE-SNAP-Result',                         self.testXTMSnapResult),
            ('55', 'X-IMSS-DKIM-White-List',                      self.testXTMDKIM),
            ('56', 'X-TM-AS-Result-Xfilter',                      self.testXTMXFilter),
            ('57', 'X-TM-AS-SMTP',                                self.testXTMASSMTP),
            ('58', 'X-TMASE-SNAP-Result',                         self.testXTMASESNAP),
            ('59', 'X-TM-Authentication-Results',                 self.testXTMAuthenticationResults),
            ('60', 'X-Scanned-By',                                self.testXScannedBy),
            ('61', 'X-Mimecast-Spam-Signature',                   self.testXMimecastSpamSignature),
            ('62', 'X-Mimecast-Bulk-Signature',                   self.testXMimecastBulkSignature),
            ('63', 'X-Forefront-Antispam-Report-Untrusted',       self.testForefrontAntiSpamReportUntrusted),
            ('64', 'X-Microsoft-Antispam-Untrusted',              self.testForefrontAntiSpamUntrusted),
            ('65', 'X-Mimecast-Impersonation-Protect',            self.testMimecastImpersonationProtect),
            ('66', 'X-Proofpoint-Spam-Details',                   self.testXProofpointSpamDetails),
            ('67', 'X-Proofpoint-Virus-Version',                  self.testXProofpointVirusVersion),
            ('68', 'SPFCheck',                                    self.testSPFCheck),
            ('69', 'X-Barracuda-Spam-Score',                      self.testXBarracudaSpamScore),
            ('70', 'X-Barracuda-Spam-Status',                     self.testXBarracudaSpamStatus),
            ('71', 'X-Barracuda-Spam-Report',                     self.testXBarracudaSpamReport),
            ('72', 'X-Barracuda-Bayes',                           self.testXBarracudaBayes),
            ('73', 'X-Barracuda-Start-Time',                      self.testXBarracudaStartTime),

            ('83', 'Office365 Tenant ID',                         self.testO365TenantID),
            ('84', 'Organization Name',                           self.testOrganizationIsO365Tenant),
            ('85', 'MS Defender for Office365 Safe Links Version',self.testSafeLinksKeyVer),
            ('87', 'AWS SES Outgoing',                            self.testXSESOutgoing),
            ('88', 'IronPort-Data',                               self.testIronPortData),
            ('89', 'IronPort-HdrOrder',                           self.testIronPortHdrOrdr),
            ('90', 'X-DKIM',                                      self.testXDKIM),
            ('91', 'DKIM-Filter',                                 self.testDKIMFilter),
            ('92', 'X-SpamExperts-Class',                         self.testXSpamExpertsClass),
            ('93', 'X-SpamExperts-Evidence',                      self.testXSpamExpertsEvidence),
            ('94', 'X-Recommended-Action',                        self.testXRecommendedAction),
            ('95', 'X-AppInfo',                                   self.testXAppInfo),
            ('96', 'X-Spam',                                      self.testXSpam),
            ('97', 'X-TM-AS-MatchedID',                           self.testXTMASMatchedID),
            ('99', 'Office365 First Contact Safety Tip',          self.testO365FirstContactSafetyTip),
            ('100','EOP - Bypass Focused Inbox',                  self.testBypassFocusedInbox),
            ('101','EOP - Enhanced Filtering - SkipListedInternetSender', self.testO365EnhancedFilteringSkipListedInternetSender),
            ('102','EOP - Enhanced Filtering - ExternalOriginalInternetSender', self.testO365EnhancedFilteringExternalOriginalInternetSender),
            ('103','Cloudmark Analysis',                          self.testCloudmarkAuthority),
            ('104','The Real Sender - via Authenticated-Sender',  self.testAuthenticatedSender),
            

            #
            # These tests shall be the last ones.
            #
            ('74', 'Similar to SpamAssassin Spam Level headers',  self.testSpamAssassinSpamAlikeLevels),
            ('75', 'SMTP Header Contained IP address',            self.testMessageHeaderContainedIP),
            ('76', 'Other unrecognized Spam Related Headers',     self.testSpamRelatedHeaders),
            ('77', 'Other interesting headers',                   self.testInterestingHeaders),
            ('78', 'Security Appliances Spotted',                 self.testSecurityAppliances),
            ('79', 'Email Providers Infrastructure Clues',        self.testEmailIntelligence),
            ('98', 'MTA Hostname Exposed',                        self.testMTAHostnamesExposed),
            ('105', 'Identified Sender Addresses',                self.testSenderAddress),

            # Make this last one, always
            ('106', 'Unsual SMTP headers',                        self.testUnusualHeaders),
        )

        testsDecodeAll = (
            ('80', 'X-Microsoft-Antispam-Message-Info',           self.testMicrosoftAntiSpamMessageInfo),
            ('81', 'Decoded Mail-encoded header values',          self.testDecodeEncodedHeaders),
        )

        testsReturningArray = (
            ('82', 'Header Containing Client IP',                 self.testAnyOtherIP),
            ('86', 'Suspicious Words in Headers',                 self.testSuspiciousWordsInHeaders),
        )

        ids = set()

        for test in (tests + testsDecodeAll + testsReturningArray):
            assert test[0] not in ids, f"Test ID already taken: ({test[0]} - '{test[1]}')! IDs must be unique!"
            ids.add(test[0])

        return (tests, testsDecodeAll, testsReturningArray)

    @staticmethod
    def safeBase64Decode(value):
        enc = False

        if type(value) == str: 
            enc = True
            value = value.encode()

        try:
            out = base64.b64decode(value)
        except:
            try:
                out = base64.b64decode(value + b'=' * (-len(value) % 4))
            except:
                out = value

        if enc:
            out = out.decode(errors = 'ignore')

        return out

    @staticmethod
    def resolveAddress(addr):
        return SMTPHeadersAnalysis.gethostbyaddr(addr)

    resolved = {}

    @staticmethod
    def gethostbyaddr(addr, important = True):
        if not important or options['dont_resolve'] or len(addr) == 0:
            return ''

        if addr in SMTPHeadersAnalysis.resolved.keys():
            logger.dbg(f'Returning cached gethostbyaddr entry for: "{addr}"')
            return SMTPHeadersAnalysis.resolved[addr]

        try:
            logger.dbg(f'gethostbyaddr("{addr}")...')
            res = socket.gethostbyaddr(addr)
            if len(res) > 0:
                logger.dbg(f'Cached gethostbyaddr("{addr}") = "{res[0]}"')
                SMTPHeadersAnalysis.resolved[addr] = res[0]
                return res[0]
        except:
            pass

        return ''

    @staticmethod
    def gethostbyname(name, important = True):
        name = name.lower()
        if not important or options['dont_resolve'] or len(name) == 0:
            return ''

        if name in SMTPHeadersAnalysis.resolved.keys():
            logger.dbg(f'Returning cached gethostbyname entry for: "{name}"')
            return SMTPHeadersAnalysis.resolved[name]
            
        try:
            logger.dbg(f'gethostbyname("{name}")...')
            res = socket.gethostbyname(name)
            if len(res) > 0:
                logger.dbg(f'Cached gethostbyname("{name}") = "{res}"')
                SMTPHeadersAnalysis.resolved[name] = res
                return res
        except:
            pass

        return ''
            
    @staticmethod
    def parseExchangeVersion(lookup):

        # Try strict matching
        for ver in SMTPHeadersAnalysis.Exchange_Versions:
            if ver.version == lookup:
                return ver

        lookupparsed = packaging.version.parse(lookup)

        # Go with version-wise comparison to fuzzily find proper version name
        sortedversions = sorted(SMTPHeadersAnalysis.Exchange_Versions)

        match = re.search(r'\d{1,}\.\d{1,}\.\d{1,}', lookup, re.I)
        if not match:
            return None

        for i in range(len(sortedversions)):
            if sortedversions[i].version.startswith(lookup):
                sortedversions[i].name = 'fuzzy match: ' + sortedversions[i].name
                return sortedversions[i]

        for i in range(len(sortedversions)):
            prevver = packaging.version.parse('0.0')
            nextver = packaging.version.parse('99999.0')
            if i > 0:
                prevver = packaging.version.parse(sortedversions[i-1].version)
            thisver = packaging.version.parse(sortedversions[i].version)
            if i + 1 < len(sortedversions):
                nextver = packaging.version.parse(sortedversions[i+1].version)

            if lookupparsed >= thisver and lookupparsed < nextver:
                sortedversions[i].name = 'fuzzy match: ' + sortedversions[i].name
                return sortedversions[i]

        return None


    def getHeader(self, _header):
        if _header not in SMTPHeadersAnalysis.Handled_Spam_Headers:
            SMTPHeadersAnalysis.Handled_Spam_Headers.append(_header)

        for (num, header, value) in self.headers:
            if header.lower() == _header.lower():
                m1 = re.search(r'\=\?[a-z0-9\-]+\?Q\?', value, re.I)
                if m1:
                    v1d = emailheader.decode_header(value)[0][0]
                    if type(v1d) == bytes:
                        v1d = v1d.decode(errors='ignore')
                    value = v1d

                return (num, header, value)

        similar_headers = (
            ('-Microsoft-', '-Exchange-'),
            ('-Microsoft-', '-Office365-'),
        )

        for sim in similar_headers:
            if sim[0].lower() in _header.lower():
                _header = re.sub(sim[0], sim[1], _header, re.I)

                for (num, header, value) in self.headers:
                    if header.lower() == _header.lower():
                        m1 = re.search(r'\=\?[a-z0-9\-]+\?Q\?', value, re.I)
                        if m1:
                            v1d = emailheader.decode_header(value)[0][0]
                            if type(v1d) == bytes:
                                v1d = v1d.decode(errors='ignore')
                            value = v1d
                        return (num, header, value)

        return (-1, '', '')

    def collect(self, text):
        num = 0
        errorOnce = False
        lines = text.split('\n')
        boundary = ''
        inBoundary = False
        headers = []
        
        i = 0
        while i < len(lines):
            line = lines[i]

            if len(boundary) > 0 and f'--{boundary}' == line.strip():
                inBoundary = True
                i += 1
                continue

            elif inBoundary and f'--{boundary}--' == line.strip():
                inBoundary = False
                i += 1
                continue

            elif inBoundary:
                i += 1
                continue

            elif line.startswith(' ') or line.startswith('\t'):
                if len(headers) > 0:
                    headers[-1][2] += '\n' + line
                    i += 1
                    continue
                else:
                    logger.dbg(f'Skipping invalid line:\n\t( {line} )')
                    i += 1
                    continue
            else:
                line = line.strip()
                match = re.match(r'^([^:]+)\s*:\s+(.+)\s*', line, re.S)

                if match:
                    headers.append([num, match.group(1), match.group(2)])
                    logger.dbg(f'Extracted {num}. {match.group(1)}')
                    num += 1
                else:
                    match = re.match(r'^([^:]+)\s*:\s*', line, re.S)

                    if match:
                        val = ''

                        considerNextLineIndented = match.group(1) in SMTPHeadersAnalysis.Headers_Known_For_Breaking_Line

                        if match and i + 1 < len(lines) and (lines[i + 1].startswith(' ') \
                                or lines[i + 1].startswith('\t')) or considerNextLineIndented:
                            j = 1

                            if considerNextLineIndented and not errorOnce and \
                                (not lines[i + 1].startswith(' ') and not lines[i+1].startswith('\t')):
                                errorOnce = True
                                self.logger.err('''
-----------------------------------------
WARNING!
-----------------------------------------

Your SMTP headers are not properly indented! 
Results will be unsound. Make sure you have pasted your headers with correct spaces/tabs indentation.

''')


                            while i + j < len(lines):
                                l = lines[i + j]

                                if l.startswith(' ') or l.startswith('\t') or considerNextLineIndented:
                                    val += l + '\n'
                                    j += 1
                                    considerNextLineIndented = False
                                else:
                                    break

                            headers.append([num, match.group(1), val.strip()])
                            logger.dbg(f'Extracted {num}. {match.group(1)}')
                            num += 1

                            i += j - 1

            if len(headers) > 0 and len(headers[-1]) > 1 and headers[-1][1].lower() == 'content-type':
                m = re.search(r'boundary="([^"]+)"', headers[-1][2], re.I)
                if m:
                    boundary = m.group(1)

            i += 1

        self.logger.info(f'Analysing {num} headers...')
        return headers

    def parse(self, text):
        self.text = text

        self.headers = self.collect(text)

        (tests, testsDecodeAll, testsReturningArray) = self.getAllTests()

        testsConducted = 0

        for testId, testName, testFunc in tests:
            try:
                if len(self.testsToRun) > 0 and int(testId) not in self.testsToRun:
                    self.logger.dbg(f'Skipping test {testId} {testName}')
                    continue

                testsConducted += 1
                self.logger.dbg(f'Running test {testId}: "{testName}"...')
                self.results[testName] = testFunc()

            except Exception as e:
                self.logger.err(f'Test {testId}: "{testName}" failed: {e} . Use --debug to show entire stack trace.')

                self.results[testName] = {
                    'header' : '',
                    'value' : '',
                    'analysis' : 'Internal script error. Use --debug to find out more what happened.',
                }

                if options['debug']:
                    raise

        idsOfDecodeAll = [int(x[0]) for x in testsDecodeAll]

        #for a in self.testsToRun:
        #    if a in idsOfDecodeAll:
        #        self.decode_all = True
        #        break

        if self.decode_all:
            for testId, testName, testFunc in testsDecodeAll:
                try:
                    if len(self.testsToRun) > 0 and int(testId) not in self.testsToRun:
                        self.logger.dbg(f'Skipping test {testId} {testName}')
                        continue
                    
                    testsConducted += 1
                    self.logger.dbg(f'Running test {testId}: "{testName}"...')
                    self.results[testName] = testFunc()

                except Exception as e:
                    self.logger.err(f'Test {testId}: "{testName}" failed: {e} . Use --debug to show entire stack trace.')

                    self.results[testName] = {
                        'header' : '',
                        'value' : '',
                        'analysis' : 'Internal script error. Use --debug to find out more what happened.',
                    }

                    if options['debug']:
                        raise

        for testId, testName, testFunc in testsReturningArray:
            try:
                if len(self.testsToRun) > 0 and int(testId) not in self.testsToRun:
                    self.logger.dbg(f'Skipping test {testId} {testName}')
                    continue
                    
                testsConducted += 1
                self.logger.dbg(f'Running test {testId}: "{testName}"...')
                outs = testFunc()

                num = 0
                for o in outs:
                    num += 1
                    self.results[testName + ' ' + str(num)] = o

            except Exception as e:
                self.logger.err(f'Test {testId}: "{testName}" failed: {e} . Use --debug to show entire stack trace.')

                self.results[testName] = {
                    'header' : '',
                    'value' : '',
                    'analysis' : 'Internal script error. Use --debug to find out more what happened.',
                }

                if options['debug']:
                    raise

        for k in self.results.keys():
            if not self.results[k] or len(self.results[k]) == 0: 
                continue

            for kk in ['description', 'header', 'value']:
                if kk not in list(self.results[k].keys()):
                    self.results[k][kk] = ''

        self.logger.dbg(f'\n------------------------------------------\nAttempted to process following SMTP headers ({len(SMTPHeadersAnalysis.Handled_Spam_Headers)}):')
        
        for header in SMTPHeadersAnalysis.Handled_Spam_Headers:
            self.logger.dbg(f'\t- {header.capitalize()}')

        self.logger.dbg('\n------------------------------------------\n\n')

        self.logger.dbg(f'Conducted {testsConducted} tests on provided SMTP headers.')

        return {k: v for k, v in self.results.items() if v}

    @staticmethod
    def flattenLine(value):
        return ' '.join([x.strip() for x in value.split('\n')])

    @staticmethod
    def printable(input_str):
        istr = str(input_str)
        return all(ord(c) < 127 and c in string.printable for c in istr)

    @staticmethod
    def extractDomain(fqdn):
        if not fqdn:
            return ''

        parts = fqdn.split('.')
        return '.'.join(parts[-2:]).replace('<','').replace('>','')

    @staticmethod
    def decodeSpamcause(msg):
        text = []
        for i in range(0, len(msg), 2):
            text.append(SMTPHeadersAnalysis.unrotSpamcause(msg[i: i + 2]))
        return str.join('', text)

    @staticmethod
    def unrotSpamcause(pair, key=ord('x')):
        offset = 0
        for c in 'cdefgh':
            if c in pair:
                offset = (ord('g') - ord(c)) * 16
                break
        return chr(sum(ord(c) for c in pair) - key - offset)

    @staticmethod
    def hexdump(data, addr = 0, num = 0):
        s = ''
        n = 0
        lines = []
        if num == 0: num = len(data)

        if len(data) == 0:
            return '<empty>'

        for i in range(0, num, 16):
            line = ''
            line += '%04x | ' % (addr + i)
            n += 16

            for j in range(n-16, n):
                if j >= len(data): break
                line += '%02x ' % (data[j] & 0xff)

            line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

            for j in range(n-16, n):
                if j >= len(data): break
                c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
                line += '%c' % c

            lines.append(line)
        return '\n'.join(lines)

    def testEmailIntelligence(self):
        service = []
        value = self.text

        #
        # NOTICE:
        #   This code below was copied from the following repository:
        #       https://github.com/nquinlan/Email-Intelligence 
        #
        #   and is authored solely by Nick Quinlan (nick@nicholasquinlan.com).
        #

        # Amazon SES
        if re.search(r'^X-SES-Outgoing:', value, re.I|re.S) or "Amazon SES" in value or "Amazon SES".lower() in value.lower() or "AmazonSES".lower() in value.lower():
            service.append(("Amazon SES", "http://aws.amazon.com/ses/"))

        # BenchmarkEmail.com
        if re.search(r'www.benchmarkemail.com', value, re.I|re.S) or "BenchmarkEmail".lower() in value.lower():
            service.append(("BenchmarkEmail", "http://benchmarkemail.com/"))

        # Bronto
        if re.search(r'd=bronto.com;', value, re.I|re.S) or "Bronto".lower() in value.lower():
            service.append(("Bronto", "http://bronto.com/"))

        # Campaign Monitor
        if re.search(r'^X-Complaints-To: abuse@cmail\d{1,2}\.com', value, re.I|re.S) or "Campaign Monitor".lower() in value.lower() or "CampaignMonitor".lower() in value.lower():
            service.append(("Campaign Monitor", "https://www.campaignmonitor.com"))

        # Constant Contact
        if re.search(r'^X-Roving-ID:', value, re.I|re.S) or "Constant Contact".lower() in value.lower() or "ConstantContact".lower() in value.lower():
            service.append(("Constant Contact", "https://www.constantcontact.com"))

        # Dyn
        if re.search(r'^X-DynectEmail-Msg-(Key|Hash):', value, re.I|re.S) or "Dyn".lower() in value.lower():
            service.append(("Dyn", "https://dyn.com/"))

        # Eloqua
        if re.search(r'^X-elqPod:', value, re.I|re.S) or "Eloqua".lower() in value.lower():
            service.append(("Eloqua", "http://www.eloqua.com/"))

        # Email Vision
        if re.search(r'^X-EMV-MemberId:', value, re.I|re.S) or "Emailvision".lower() in value.lower():
            service.append(("Emailvision", "https://www.emailvision.com/"))

        # Emma
        if re.search(r'd=e2ma\.net;', value, re.I|re.S) or "Emma".lower() in value.lower():
            service.append(("Emma", "https://myemma.com/"))

        # ExactTarget
        if re.search(r'^x-job: \d{3,}_\d{3,}$', value, re.I|re.S) and re.search(r'mta[\d]*\.[\w-\.]+\.[a-z]{2,}', value, re.I|re.S) or "ExactTarget".lower() in value.lower():
            service.append(("ExactTarget", "http://www.exacttarget.com/"))

        # Fishbowl
        if re.search(r'^X-Mailer: Fishbowl', value, re.I|re.S) or "Fishbowl".lower() in value.lower():
            service.append(("Fishbowl", "https://www.fishbowl.com/"))

        # Gold Lasso
        if re.search(r'^X-Mailer: Eloop Mailer', value, re.I|re.S) or "Gold Lasso".lower() in value.lower() or "GoldLasso".lower() in value.lower():
            service.append(("Gold Lasso", "https://www.goldlasso.com/"))

        # Google App Engine
        if re.search(r'^X-Google-Appengine-App-Id:', value, re.I|re.S) or "Google App Engine".lower() in value.lower() or "GoogleApp".lower() in value.lower() or "AppEngine".lower() in value.lower():
            service.append(("Google App Engine", "https://developers.google.com/appengine/docs/python/mail/sendingmail"))

        # iContact
        if re.search(r'^X-ICPINFO:', value, re.I|re.S) or "iContact".lower() in value.lower():
            service.append(("iContact", "https://www.icontact.com/"))

        # Listrak
        if re.search(r'^Received: from [\w-]+\.listrak\.com', value, re.I|re.S) or "Listrak".lower() in value.lower():
            service.append(("Listrak", "https://www.listrak.com/"))

        # Locaweb
        if re.search(r'^x-locaweb-id:', value, re.I|re.S) or "Locaweb".lower() in value.lower():
            service.append(("Locaweb", "https://www.locaweb.com.br/"))

        # Mailchimp
        if re.search(r'^X-MC-User:', value, re.I|re.S) or "MailChimp".lower() in value.lower():
            service.append(("MailChimp", "https://mailchimp.com/"))
        
        # MailerLite
        if re.search(r'd=ml.mailersend.com;', value, re.I|re.S) or "MailerLite".lower() in value.lower():
            service.append(("MailerLite", "https://www.mailerlite.com/"))
        
        # Mailgun
        if re.search(r'^X-Mailgun-Sid:', value, re.I|re.S) or re.search(r'X-Mailgun-Variables:', value, re.I|re.S) or "Mailgun".lower() in value.lower():
            service.append(("Mailgun", "https://www.mailgun.com/"))

        # Mailigen
        if re.search(r'^X-Mailer: MailiGen', value, re.I|re.S) or "Mailigen".lower() in value.lower():
            service.append(("Mailigen", "http://www.mailigen.com/"))

        # Mailjet
        if re.search(r's=mailjet;', value, re.I|re.S) or "Mailjet".lower() in value.lower():
            service.append(("Mailjet", "https://www.mailjet.com/"))

        # Mandrill
        if re.search(r'^X-Mandrill-User:', value, re.I|re.S) or "Mandrill".lower() in value.lower():
            service.append(("Mandrill", "https://mandrillapp.com/"))

        # Marketo
        if re.search(r'^X-MarketoID:', value, re.I|re.S) or "Marketo".lower() in value.lower():
            service.append(("Marketo", "https://www.marketo.com/"))

        # Message Bus
        if re.search(r'^X-Messagebus-Info:', value, re.I|re.S) or "Message Bus".lower() in value.lower() or "MessageBus".lower() in value.lower():
            service.append(("Message Bus", "https://messagebus.com/"))

        # Mixmax
        if re.search(r'^X-Mailer: Mixmax', value, re.I|re.S) or "Mixmax".lower() in value.lower():
            service.append(("Mixmax", "https://mixmax.com/"))

        # Postmark
        if re.search(r'^X-PM-Message-Id:', value, re.I|re.S) or "Postmark".lower() in value.lower():
            service.append(("Postmark", "https://postmarkapp.com/"))

        # Responsys
        if re.search(r'^X-rext:', value, re.I|re.S) or "Responsys".lower() in value.lower():
            service.append(("Responsys", "https://www.responsys.com/"))

        # Sailthru
        if re.search(r'^X-Mailer: sailthru.com$', value, re.I|re.S) or "Sailthru".lower() in value.lower():
            service.append(("Sailthru", "https://www.sailthru.com/"))

        # Salesforce
        if re.search(r'^X-SFDC-User:', value, re.I|re.S) or "Salesforce".lower() in value.lower():
            service.append(("Salesforce", "https://www.salesforce.com/"))

        # SendGrid
        if re.search(r'^X-(SG|SENDGRID)-EID:', value, re.I|re.S) or "SendGrid".lower() in value.lower():
            service.append(("SendGrid", "https://sendgrid.com/"))

        # Silverpop
        if re.search(r'^Received: from [\w\.]+\.mkt\d{3,}\.com', value, re.I|re.S): # Not proprietary, but likely only Silverpo or "Silverpop".lower() in value.lower()p
            service.append(("Silverpop", "https://www.silverpop.com/"))

        # SMTP.com
        if re.search(r'^X-SMTPCOM-Tracking-Number:', value, re.I|re.S) or "SMTP.com".lower() in value.lower():
            service.append(("SMTP.com", "https://smtp.com/"))

        # VerticalResponse
        if re.search(r'^X-vrfbldomain:', value, re.I|re.S) and re.search(r'^X-vrpod:', value, re.I|re.S) and re.search(r'^X-vrrpmm:', value, re.I|re.S) or "VerticalResponse".lower() in value.lower():
            service.append(("VerticalResponse", "http://www.verticalresponse.com/"))

        # Yesmail
        if re.search(r's=yesmail.?;', value, re.I|re.S) or re.search(r'^Received: from [\w\.\-]+postdirect.com', value, re.I|re.S) or "Yesmail".lower() in value.lower():
            service.append(("Yesmail", "https://www.yesmail.com/"))

        if len(service) == 0:
            return []

        result = f'- Mail contents analysis shown that this e-mail passed through the following third-party Mail providers:\n\n'

        for svc in service:
            svcname = self.logger.colored(svc[0], 'green')
            result += f'\t- {svcname} - url: {svc[1]}\n'

        return {
            'header': '',
            'value' : '',
            'analysis' : result,
            'description' : '',
        }

    def testSafeLinksKeyVer(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-Safelinks-Url-KeyVer')
        if num == -1: return []

        value = value.strip()
        self.addSecurityAppliance('MS Defender for Office365 - Safe Links')
        result = f'- Microsoft Defender for Office365 (MDO) Safe Links was used in key version: {self.logger.colored(value, "green")}\n'        
        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testSecurityAppliances(self):
        result = ''
        vals = [x.lower() for x in SMTPHeadersAnalysis.Header_Keywords_That_May_Contain_Spam_Info]
        vals += [x[0].lower() for x in SMTPHeadersAnalysis.Security_Appliances_And_Their_Headers]
        vals += [x[0].lower() for x in SMTPHeadersAnalysis.Security_Appliances_And_Their_Values]
        vals += [x.lower() for x in SMTPHeadersAnalysis.Manually_Added_Appliances]

        self.logger.dbg('Spotted clues about security appliances:')

        for (num, header, value) in self.headers:
            for product, hdr in SMTPHeadersAnalysis.Security_Appliances_And_Their_Headers:
                if re.search(re.escape(hdr), header, re.I):
                    self.securityAppliances.add(product)

            for product, val in SMTPHeadersAnalysis.Security_Appliances_And_Their_Values:
                if re.search(re.escape(val), value, re.I):
                    self.securityAppliances.add(product)

        for a in self.securityAppliances:
            parts = a.split(' ')
            skip = True

            self.logger.dbg(f'\t- {a}')

            for p in parts:
                if p.lower() in vals:
                    skip = False
                    break

            if skip: 
                continue

            result += f'\t- {self.logger.colored(a, "yellow")}\n'

        if len(result) == 0:
            return []

        return {
            'header': '',
            'value' : '',
            'analysis' : '- During headers analysis, spotted following clues about Security Appliances:\n\n' + result,
            'description' : '',
        }

    @staticmethod
    def getOffice365TenantNameById(tenantID):
        url = 'https://login.microsoftonline.com/TENANT_ID/oauth2/authorize?client_id=TENANT_ID&response_type=id_token&redirect_uri=http%3a%2f%2flocalhost%2fmyapp%2f&response_mode=form_post&scope=openid&state=12345&nonce=678910'
        url = url.replace('TENANT_ID', tenantID)

        try:
            r = requests.get(
                url, 
                allow_redirects=True,
                headers = {
                    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4600.00 Safari/537.36',
                })

            out = r.text

            if 'AADSTS700016'.lower() in out.lower():
                m = re.search(r"was not found in the directory '([^']+)'", out, re.I)
                if m:
                    return m.group(1)

        except:
            pass
        
        return ''

    def testO365TenantID(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-CrossTenant-Id')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value).strip().replace(' ', '')
        result = f'- Office365 Tenant ID: {self.logger.colored(value, "cyan")}\n'
        self.addSecurityAppliance('Office365')

        try:
            r = requests.get(f'https://login.microsoftonline.com/{value}/.well-known/openid-configuration')
            out = r.json()

            #
            # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
            #
            #
            # Sample response for "microsoft.com":
            #   https://login.microsoftonline.com/microsoft.com/.well-known/openid-configuration
            #
            # RESPONSE:
            # {
            #   "token_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token",
            #   "token_endpoint_auth_methods_supported": [
            #     "client_secret_post",
            #     "private_key_jwt",
            #     "client_secret_basic"
            #   ],
            #   "jwks_uri": "https://login.microsoftonline.com/common/discovery/keys",
            #   "response_modes_supported": [
            #     "query",
            #     "fragment",
            #     "form_post"
            #   ],
            #   "subject_types_supported": [
            #     "pairwise"
            #   ],
            #   "id_token_signing_alg_values_supported": [
            #     "RS256"
            #   ],
            #   "response_types_supported": [
            #     "code",
            #     "id_token",
            #     "code id_token",
            #     "token id_token",
            #     "token"
            #   ],
            #   "scopes_supported": [
            #     "openid"
            #   ],
            #   "issuer": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
            #   "microsoft_multi_refresh_token": true,
            #   "authorization_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/authorize",
            #   "device_authorization_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/devicecode",
            #   "http_logout_supported": true,
            #   "frontchannel_logout_supported": true,
            #   "end_session_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/logout",
            #   "claims_supported": [
            #     "sub",
            #     "iss",
            #     "cloud_instance_name",
            #     "cloud_instance_host_name",
            #     "cloud_graph_host_name",
            #     "msgraph_host",
            #     "aud",
            #     "exp",
            #     "iat",
            #     "auth_time",
            #     "acr",
            #     "amr",
            #     "nonce",
            #     "email",
            #     "given_name",
            #     "family_name",
            #     "nickname"
            #   ],
            #   "check_session_iframe": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/checksession",
            #   "userinfo_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/openid/userinfo",
            #   "kerberos_endpoint": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/kerberos",
            #   "tenant_region_scope": "WW",
            #   "cloud_instance_name": "microsoftonline.com",
            #   "cloud_graph_host_name": "graph.windows.net",
            #   "msgraph_host": "graph.microsoft.com",
            #   "rbac_url": "https://pas.windows.net"
            # }

            if 'error' in out.keys() and out['error'] != '':
                m = out['error']
                result += '\t- Office365 Tenant ' + self.logger.colored(f'does not exist: {m}\n', 'red')
            else:
                result += '\t- Office365 Tenant ' + self.logger.colored(f'exists.', 'yellow')

                name = SMTPHeadersAnalysis.getOffice365TenantNameById(value)
                if len(name) > 0:
                    result += ' named as: ' + self.logger.colored(name, "green")

                result += '\n'

                tmp = ''

                num0 = 0
                for (num1, header1, value1) in self.headers:
                    value1 = SMTPHeadersAnalysis.flattenLine(value1).strip()
                    if value.lower() in value1.lower() and header1.lower() != header.lower():
                        num0 += 1
                        pos = value1.lower().find(value.lower())
                        val = value1
                        if pos != -1:
                            val = value1[:pos] + self.logger.colored(value1[pos:pos+len(value)], 'yellow') + value1[pos+len(value):]

                        tmp += f'\t- ({num0:02}) Header: {self.logger.colored(header1, "magenta")}\n'
                        tmp += f'\t        Value: {val}\n\n'

                if len(tmp) > 0:
                    result += '\n    - Tenant ID found in following headers:\n'
                    result += '\n' + tmp + '\n'

        except:
            self.logger.err(f'Could not fetch Office365 tenant OpenID configuration. Use --debug for more details.')
            result += self.logger.colored('\t- Error: Could not fetch information about Office365 Tenant.\n', 'red')

            if options['debug']:
                raise

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }


    def testOrganizationIsO365Tenant(self):
        (num, header, value) = self.getHeader('X-OriginatorOrg')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value).strip()

        result = f'- Organization name disclosed: {self.logger.colored(value, "green")}\n'
        self.addSecurityAppliance('Office365')

        try:
            r = requests.get(f'https://login.microsoftonline.com/{value}/.well-known/openid-configuration')
            out = r.json()

            if 'error' in out.keys() and out['error'] != '':
                m = out['error']
                return []

            result += '\n    - Organization disclosed in "X-OriginatorOrg" is a valid Office 365 Tenant:\n'
            tid = out['token_endpoint'].replace('https://login.microsoftonline.com/', '')
            tid = tid.replace('/oauth2/token', '')

            result += '\t- Office365 Tenant ID: ' + self.logger.colored(tid, 'green') + '\n'
            tmp = ''

            num0 = 0
            for (num1, header1, value1) in self.headers:
                value1 = SMTPHeadersAnalysis.flattenLine(value1).strip()
                if value.lower() in value1.lower() and header1.lower() != header.lower():
                    num0 += 1
                    pos = value1.lower().find(value.lower())
                    val = value1
                    if pos != -1:
                        val = value1[:pos] + self.logger.colored(value1[pos:pos+len(value)], 'yellow') + value1[pos+len(value):]

                    tmp += f'\t- ({num0:02}) Header: {self.logger.colored(header1, "magenta")}\n'
                    tmp += f'\t        Value: {val}\n\n'

            if len(tmp) > 0:
                result += '\n    - Organization name was also found in following headers:\n'
                result += '\n' + tmp + '\n'

        except:
            self.logger.err(f'Could not fetch Office365 tenant OpenID configuration.')

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXProofpointSpamDetails(self):
        (num, header, value) = self.getHeader('X-Proofpoint-Spam-Details')
        if num == -1: return []

        result = '- Proofpoint Email Protection Spam details report\n'
        self.addSecurityAppliance('Proofpoint Email Protection')
        return self._parseProofpoint(result, '', num, header, value)

    def _parseProofpoint(self, topic, description, num, header, value):
        value = SMTPHeadersAnalysis.flattenLine(value)
        parts = value.split(' ')

        result = topic

        for part in parts:
            if '=' not in part:
                result += f'\t- {part}\n'
            else:
                (k, v) = part.split('=')

                col = 'yellow'
                if k.lower() == 'rule':
                    if v.lower() == 'notspam': col = 'green'
                    elif v.lower() == 'spam': col = 'red'
                    elif 'definitive' in v.lower(): col = 'red'
                    elif 'malware' in v.lower(): col = 'red'
                    elif 'phish' in v.lower(): col = 'red'
                    elif 'quarantine' in v.lower(): col = 'red'

                    v = self.logger.colored(v.upper(), col)

                elif k.lower() == 'vendor':
                    v = self.logger.colored(v, 'green')                    

                else:
                    try:
                        num = float(v)
                        if num > 0:
                            v = self.logger.colored(v, 'yellow')
                        else:
                            v = self.logger.colored(v, 'green')

                    except:
                        pass

                result += f'\t- {k: <20}: {v}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : description,
        }

    def testXProofpointVirusVersion(self):
        (num, header, value) = self.getHeader('X-Proofpoint-Virus-Version')
        if num == -1: return []

        result = '- Proofpoint Email Protection Anti-Virus version\n'
        self.addSecurityAppliance('Proofpoint Email Protection')
        return self._parseProofpoint(result, '', num, header, value)


    def testAuthenticatedSender(self):
        (num, header, value) = self.getHeader('X-Authenticated-Sender')
        if num == -1: return []

        result = '- This user has authenticated to the mail server to send that e-mail:\n'
        result += f'\t- {self.logger.colored(value, "green")}\n'

        (num1, header1, value1) = self.getHeader('From')

        if header1 and value1:
            if value.lower() not in value1.lower():
                result += f'\n\t- {self.logger.colored("Mismatch with From header!", "red")}\n'
                result += f'\t\t- Authenticated user is not the same as declared in From header:\n\n'
                result += f'\t\t\t- Authenticated as:\t{self.logger.colored(value, "red")}\n'
                result += f'\t\t\t- Sent e-mail as:  \t{self.logger.colored(value1, "green")}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }
        

    def testXSpamExpertsClass(self):
        (num, header, value) = self.getHeader('X-SpamExperts-Class')
        if num == -1: return []

        result = f'- n-able Mail Assure (SpamExperts) Class: {self.logger.colored(value, "yellow")}\n'

        if value.lower() in SMTPHeadersAnalysis.SpamExperts_Classes.keys():
            result += f'\n\t- {value}: ' + SMTPHeadersAnalysis.SpamExperts_Classes[value.lower()] + '\n'

        self.addSecurityAppliance('n-able Mail Assure (SpamExperts)')
        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXSpamExpertsEvidence(self):
        (num, header, value) = self.getHeader('X-SpamExperts-Evidence')
        if num == -1: return []

        result = f'- n-able Mail Assure (SpamExperts) Evidence:\n\t- {self.logger.colored(value, "magenta")}\n'

        m = re.match(r'.+\s+\(([\.\d]+)\).*', value)
        if m:
            try:
                score = float(m.group(1))
                col = 'yellow'
                msg = ''
                
                if score < 0.5:
                    col = 'green'
                    msg = self.logger.colored('Message not quarantined and considered harmless.', col)

                elif score < 0.9:
                    col = 'yellow'
                    msg = self.logger.colored('Message not quarantined but raised some suspicions', col)

                else:
                    col = 'red'
                    msg = self.logger.colored('Message quarantined.', col)

                result += f'\t- Score:   {self.logger.colored(score, col)}\n'
                result += f'\t- Verdict: {msg}\n'

            except:
                pass
            
        self.addSecurityAppliance('n-able Mail Assure (SpamExperts)')
        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXRecommendedAction(self):
        (num, header, value) = self.getHeader('X-Recommended-Action')
        if num == -1: return []

        result = f'- n-able Mail Assure (SpamExperts) Recommended Action on e-mail: {self.logger.colored(value, "yellow")}\n'

        if value.lower() in SMTPHeadersAnalysis.SpamExperts_Actions.keys():
            result += f'\n\t- {value}: ' + SMTPHeadersAnalysis.SpamExperts_Actions[value.lower()] + '\n'

        self.addSecurityAppliance('n-able Mail Assure (SpamExperts)')
        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMVersion(self):
        (num, header, value) = self.getHeader('X-TMASE-Version')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam Engine (TMASE) Version\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        parts = value.split('-')

        if len(parts) > 0: result += f'\t\t- Vendor Product Name:       {parts[0]}\n'
        if len(parts) > 1: result += f'\t\t- Product Version:           {parts[1]}\n'
        if len(parts) > 2: result += f'\t\t- Anti-Spam Enginge Version: {parts[2]}\n'
        if len(parts) > 3: result += f'\t\t- Spam Pattern Version:      {parts[3]}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def _parseThresholdsBasedScore(self, value, thresholds):
        score = 0
        try:
            score = float(value.strip())
        except:
            return ''

        for step in thresholds:
            if score >= step[0] and score <= step[1]:
                return step[2]

        return ''

    def testXBarracudaSpamScore(self):
        (num, header, value) = self.getHeader('X-Barracuda-Spam-Score')
        if num == -1: return []

        result = '- Barracuda Email Security Spam Score\n'
        self.addSecurityAppliance('Barracuda Email Security')

        thresholds = SMTPHeadersAnalysis.Barracuda_Score_Thresholds
        aggressive = False

        if aggressive:
            thresholds = SMTPHeadersAnalysis.Barracuda_Aggressive_Score_Thresholds

        score = self._parseThresholdsBasedScore(value, thresholds)
        result += f'\t- Score: {value.strip()}'

        if score != '':
            result += f' - {score}'

        return {
            'header': header,
            'value' : value,
            'analysis' : result + '\n',
            'description' : '',
        }

    def testXBarracudaSpamStatus(self):
        (num, header, value) = self.getHeader('X-Barracuda-Spam-Status')
        if num == -1: return []

        result = '- Barracuda Email Security Spam Status (based on SpamAssassin)\n\n'
        self.addSecurityAppliance('Barracuda Email Security')

        thresholds = SMTPHeadersAnalysis.Barracuda_Score_Thresholds
        aggressive = False

        if aggressive:
            thresholds = SMTPHeadersAnalysis.Barracuda_Aggressive_Score_Thresholds

        return self._parseSpamAssassinStatus(result, '', num, header, value, thresholds)

    def testSuspiciousWordsInHeaders(self):
        outputs = []
        headers = set()

        skip_headers = (
            'authentication-results',
            'received-spf',
        )

        for (num, header, value) in self.headers:
            headers.add(header.lower())

        for header in headers:
            if header.lower() in skip_headers: 
                continue

            (num, hdr, value) = self.getHeader(header)
            if num != -1:
                outputs.append(self._findSuspiciousWords(num, hdr, value))

        return outputs

    def _findSuspiciousWords(self, num, header, value):
        foundWords = set()
        totalChecked = 0
        totalFound = 0

        result = ''

        false_positives = (
            'unsubscribe',
        )

        for title, words in SMTPHeadersAnalysis.Suspicious_Words.items():
            found = set()

            for word in words[1]:
                if word.lower() in foundWords or word.lower() in false_positives: 
                    continue

                totalChecked += 1
                m = re.search(r'\b(' + re.escape(word) + r')\b', value, re.I)
                if m:
                    w = m.group(1)

                    pos = value.lower().find(w.lower())
                    pos2 = value.lower().find(w.lower() + '=')

                    if pos2 != -1 and ' ' not in w and w.lower() == w:
                        continue

                    found.add(w)
                    foundWords.add(w)

                    if pos != -1:
                        value = value[:pos] + self.logger.colored(w, "red") + value[pos + len(w):]

            if len(found) > 0:
                totalFound += len(found)
                result += f'- Found {logger.colored(len(found), "red")} {logger.colored(title, "yellow")} words {logger.colored(words[0], "cyan")}:\n'

                for w in found:
                    result += f'\t- {self.logger.colored(w, "red")}\n'

                result += '\n'

        if totalFound == 0:
            return []

        result2 = f'- {self.logger.colored(header, "cyan")} header contained {logger.colored(str(totalFound) + " suspicious words", "red")} (out of {totalChecked} total checked).\n\n'
        result2 += result

        return {
            'header' : header,
            'value' : value,
            'analysis' : result2
        }

    def testXBarracudaSpamReport(self):
        (num, header, value) = self.getHeader('X-Barracuda-Spam-Report')
        if num == -1: return []

        result = f'- Barracuda Email Security Spam Report:\n\t- {value.strip()}\n'
        self.addSecurityAppliance('Barracuda Email Security')

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXBarracudaBayes(self):
        (num, header, value) = self.getHeader('X-Barracuda-Bayes')
        if num == -1: return []

        result = f'- Barracuda Email Security Spam Bayesian analysis:\n\t- {value.strip()}\n'
        self.addSecurityAppliance('Barracuda Email Security')

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXBarracudaStartTime(self):
        (num, header, value) = self.getHeader('X-Barracuda-Start-Time')
        if num == -1: return []

        ts = int(value.strip())
        val = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        
        result = f'- Barracuda Email Security Start Time: {self.logger.colored(val, "green")} ({ts})\n'
        self.addSecurityAppliance('Barracuda Email Security')

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }
        
    def testXTMProductVer(self):
        (num, header, value) = self.getHeader('X-TM-AS-Product-Ver')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam Engine (TMASE) Version\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        parts = value.split('-')

        if len(parts) > 0: result += f'\t\t- Vendor Product Name:       {parts[0]}\n'
        if len(parts) > 1: result += f'\t\t- Product Version:           {parts[1]}\n'
        if len(parts) > 2: result += f'\t\t- Anti-Spam Enginge Version: {parts[2]}\n'
        if len(parts) > 3: result += f'\t\t- Spam Pattern Version:      {parts[3]}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testAnyOtherIP(self):
        outputs = []

        for (num, header, value) in self.headers:
            if header.lower().endswith('-ip'):

                result = f'- Connecting Client IP detected in header {header}:'
                outputs.append(self._originatingIPTest(result, '', num, header, value))

        return outputs


    def testXTMApprSender(self):
        (num, header, value) = self.getHeader('X-TM-AS-User-Approved-Sender')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')

        if value.strip().lower() == 'yes': 
            result += self.logger.colored('\t- system Approved this Sender\n', 'green')

        if value.strip().lower() == 'no': 
            result += self.logger.colored('\t- system did not Approve this Sender\n', 'red')

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testMimecastImpersonationProtect(self):
        (num, header, value) = self.getHeader('X-Mimecast-Impersonation-Protect')
        if num == -1: return []

        result = '- Mimecast mail impersonation report:\n\n'
        self.addSecurityAppliance('Mimecast')

        value = SMTPHeadersAnalysis.flattenLine(value)

        for line in value.split(';'):
            if '=' in line:
                (a, b) = line.split('=')
                a = a.strip()
                b = b.strip()
                
                if b.lower() == 'false':
                    b = self.logger.colored(b, 'green')

                elif b.lower() == 'true':
                    b = self.logger.colored(b, 'red')
                    a = self.logger.colored(a, 'red')

                if a.lower() == 'policy':
                    b = self.logger.colored(b, 'magenta')

                result += f'\t- {a}: {b}\n'
            else:
                result += f'\t- {line}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMBlockSender(self):
        (num, header, value) = self.getHeader('X-TM-AS-User-Blocked-Sender')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')

        if value.strip().lower() == 'yes': 
            result += self.logger.colored('\t- system Blocked this Sender\n', 'red')

        if value.strip().lower() == 'no': 
            result += '\t- system did not Block this Sender\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMASMatchedID(self):
        (num, header, value) = self.getHeader('X-TM-AS-MatchedID')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\n', '')

        try:
            rules = sorted([int(x) for x in value.strip().split('-')])

            result = f'- Trend Micro Anti-Spam triggered following {self.logger.colored(len(rules), "yellow")} rules on this e-mail:\n\n'

            for rule in rules:
                result += f'\t- {rule}\n'
        
        except:
            result = f'- Trend Micro Anti-Spam triggered following rules on this e-mail:\n\n'
            result += f'{value}\n'

        self.addSecurityAppliance('Trend Micro Anti-Spam')
        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMASESNAP(self):
        (num, header, value) = self.getHeader('X-TMASE-SNAP-Result')
        if num == -1: return []

        result = '- Trend Micro Anti Spam Engine (TMASE) Social Engineering Attack Protection (SNAP) scan result\n\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')

        parts = value.strip().split('-')

        if len(parts) > 0: result += f'\t- System Version:        {parts[0]}\n'
        if len(parts) > 1: result += f'\t- Scan Result:           {parts[1]}\n'
        if len(parts) > 2: result += f'\t- Scan Aggressive Level: {parts[2]}\n'
        if len(parts) > 3: 
            result += f'\t- Traverse List:'

            if ',' in parts[3]:
                num = 0
                for s in parts[3].split(','):
                    num += 1
                    rule, matched = s.split(':')

                    if matched == '0':
                        m = 'not matched'
                    else:
                        m = m = self.logger('matched', 'red')
                        matched = self.logger.red(matched, 'red')

                    if num == 1:
                        result += f'         - rule: {rule} - matched: {matched} ({m})\n'
                    else:
                        result += f'\t\t\t\t - rule: {rule} - matched: {matched} ({m})\n'
            else:
                result += f'\t\t- {parts[3]}\n'

        if len(parts) > 4: result += f'\t- Unknown:               {parts[4]}\n'

        
        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMDKIM(self):
        (num, header, value) = self.getHeader('X-IMSS-DKIM-White-List')
        if num == -1: return []

        self.addSecurityAppliance('Trend Micro InterScan Messaging Security')

        if value.strip().lower() == 'yes': 
            result = '- Trend Micro InterScan Messaging Security DKIM White Listed this sender\n'

        if value.strip().lower() == 'no': 
            result = '- Trend Micro InterScan Messaging Security did not DKIM White List this sender\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMResult(self):
        (num, header, value) = self.getHeader('X-TM-AS-Result')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam Result\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        return self._parseTMASResult(result, '', num, header, value)

    def testXTMASEResult(self):
        (num, header, value) = self.getHeader('X-TMASE-Result')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam Engine (TMASE) Result\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        return self._parseTMASResult(result, '', num, header, value)

    def testXTMScanDetails(self):
        (num, header, value) = self.getHeader('X-IMSS-Scan-Details')
        if num == -1: return []

        result = '- Trend Micro InterScan Messaging Security Scan Details\n'
        self.addSecurityAppliance('Trend Micro InterScan Messaging Security')
        return self._parseTMASResult(result, '', num, header, value)

    def _parseTMASResult(self, topicLine, description, num, header, value):
        value = value.replace('--', '-=')
        parts = value.split('-')

        result = topicLine

        thresh = 0
        if len(parts) > 2: 
            try:
                thresh = float(parts[2])
            except:
                pass

        score = 0
        if len(parts) > 1: 
            score = parts[1]
            if parts[1].startswith('='):
                score = '-' + score[1:]

            try:
                score = float(score)
            except:
                pass

        col = 'yellow'
        if score != 0 and thresh != 0:
            if score < thresh: 
                col = 'green'

            elif score >= thresh: 
                col = 'red'

        if len(parts) > 0: 
            val2 = ''
            val = parts[0].strip()

            if val.strip().lower() == 'yes': 
                val = self.logger.colored(val.upper(), col)

            if val.strip().lower() == 'no': 
                val = self.logger.colored(val.upper(), col)
                val2 = '      (SPS filter did not trigger)'

            result += f'\t\t- Is it SPAM?:         {val}{val2}\n'

        if len(parts) > 1: 
                if parts[1].startswith('='): parts[1] = '-' + parts[1][1:]
                result += f'\t\t- Trend/Spam Score:    {self.logger.colored(parts[1], col)}\n'

        if len(parts) > 2: 
            result += f'\t\t- Detection Threshold: {parts[2]}\n'

        if len(parts) > 3: 
            result += f'\t\t- Category :           {parts[3]}\n'

        if len(parts) > 4: 
            result += f'\t\t- Trend Type :         {parts[4]}'

            try:
                t = int(parts[4])
                if t in SMTPHeadersAnalysis.Trend_Type_AntiSpam.keys():
                    result += '  (' + SMTPHeadersAnalysis.Trend_Type_AntiSpam[k] + ')'
            except:
                pass

            result += '\n'

        return {
            'header': header,
            'value' : value.replace('-=', '--'),
            'analysis' : result,
            'description' : description,
        }

    def testXScannedBy(self):
        hdrs = (
            'X-Scanned-By',
            'X-ScannedBy',
            'XScannedBy',
            'XScanned-By',
            'X-Scanned',
            'X-Scan',
            'X-Scan-By',
        )

        for hdr in hdrs:
            (num, header, value) = self.getHeader(hdr)
            if num == -1: continue

            val = self.logger.colored(value, "yellow")
            result = f'- Scanned by: {val}\n'

            return {
                'header': header,
                'value' : value,
                'analysis' : result,
                'description' : '',
            }

        return []

    def testXTMSnapResult(self):
        (num, header, value) = self.getHeader('X-TMASE-SNAP-Result')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam Engine (TMASE) SNAP Result\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        result += f'\t- {value}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }
        
    def testXTMXFilter(self):
        (num, header, value) = self.getHeader('X-TM-AS-Result-Xfilter')
        if num == -1: return []

        result = '- Trend Micro Anti-Spam XFilter\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        result += f'\t- {value}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testCloudmarkAuthority(self):
        (num, header, value) = self.getHeader('X-CNFS-Analysis')
        if num == -1: return []

        result = f'- Cloudmark Authority Engine (CMAE) analysis results:\n\n'
        value = SMTPHeadersAnalysis.flattenLine(value)

        parts = {}

        for part in value.split(' '):
            pos = part.find('=')
            if pos == -1:
                parts['Value'] = part
                continue

            k = part[:pos]
            v = part[pos+1:]

            if k in parts.keys():
                if not (type(parts[k]) == type([])):
                    parts[k] = [parts[k], v]
                else:
                    parts[k].append(v)
            else:
                parts[k] = v

        self.addSecurityAppliance('Cloudmark Security Platform')

        for k, v in parts.items():
            if 'v' == k:
                result += f'\t- Version:\t\t{parts["v"]}\n'
            
            elif 'ts' == k:
                try:
                    ts = int(parts['ts'], 16)
                    ts2 = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                    result += f'\t- Timestamp:\t\t{ts2}\n'

                except Exception as e:
                    raise


            elif 'p' == k:
                result += f'\t- {self.logger.colored("Possible SPAM", "red")}:\t{parts["v"]}\n'

            else:
                if type(v) == type([]):
                    result += f'\t- {self.logger.colored(k, "magenta")} ({len(v)} entries):\n'
                    for a in v:
                        a1 = a

                        if ':' in a1:
                            b, c = a1.split(':')
                            a1 = f'{self.logger.colored(c, "yellow")}\t- {b}'

                            if self.decode_all:
                                try:
                                    dec = SMTPHeadersAnalysis.safeBase64Decode(b[:30])
                                    hd = SMTPHeadersAnalysis.hexdump(dec.encode())
                                    a1 += f'\n\t\t\t{hd} ...\n'

                                except:
                                    pass

                        result += f'\t\t- {a1}\n'
                else:
                    v1 = v
                    if ':' in v:
                        a, b = v.split(':')
                        v1 = f'{self.logger.colored(b, "yellow")} - {a}'

                    result += f'\t- {self.logger.colored(k, "magenta")}:\t\t\t{v1}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testSPFCheck(self):
        (num, header, value) = self.getHeader('SPFCheck')
        if num == -1: return []

        result = f'- SPF Check:\n'
        for line in value.split(','):
            result += f'\t- {line.strip()}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXTMASSMTP(self):
        (num, header, value) = self.getHeader('X-TM-AS-SMTP')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value)
        result = '- Trend Micro Anti-Spam SMTP servers\n'
        self.addSecurityAppliance('Trend Micro Anti-Spam')
        parts = value.split(' ')

        if len(parts) > 2:
            try:
                p2 = float(parts[0])
                result += f'\t- Priority:    {p2}\n'

            except:
                result += f'\t- Priority:    {parts[0]}\n'

            result += f'\t- Server:      {SMTPHeadersAnalysis.safeBase64Decode(parts[1])}\n'
            result += f'\t- Recipient:   {SMTPHeadersAnalysis.safeBase64Decode(parts[2])}\n'

        return {
            'header': header,
            'value' : value,
            'analysis' : result,
            'description' : '',
        }

    def testXVirusScan(self):
        (num, header, value) = self.getHeader('X-Virus-Scanned')
        if num == -1: return []

        result = f'- Message was scanned with an Anti-Virus.'
        self.addSecurityAppliance('Unknown Anti-Virus')

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXFireEye(self):
        (num, header, value) = self.getHeader('X-FireEye')
        if num == -1: return []

        result = f'- Message was scanned with FireEye Email Security Solution. Result is following:\n'
        self.addSecurityAppliance('FireEye Email Security Solution')
        result += f'\t- {self.logger.colored(value, "green")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXAntiAbuse(self):
        result = ''
        tmp = '\n'

        SMTPHeadersAnalysis.Handled_Spam_Headers.append('x-antiabuse')

        for num, header, value in self.headers:
            if header.lower() != 'x-antiabuse': 
                continue

            tmp += '        ' + SMTPHeadersAnalysis.flattenLine(value) + '\n'

        if len(tmp) > 5:
            result = f'''
    - Anti-Abuse message was included in mail headers:
        {tmp}
'''
        else:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result,
            'description' : '',
        }

    def testMessageHeaderContainedIP(self):
        result = ''
        shown = set()
        num0 = 0
        tmp = ''

        for num, header, value in self.headers:
            if header in shown or header in SMTPHeadersAnalysis.Handled_Spam_Headers: 
                continue

            ipaddr = ''
            match = re.search(r'(.{,5}\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b.{,5})', value)
            
            if match:
                ipaddr = match.group(1)

            elif header.lower().endswith('-ip'):
                ipaddr = value

            if len(ipaddr) > 0:
                SMTPHeadersAnalysis.Handled_Spam_Headers.append(header)

                num0 += 1
                tmp += f'\t({num0:02}) Header: {self.logger.colored(header, "yellow")}  contained an IP address:\n'
                
                shown.add(header)

                resolved = SMTPHeadersAnalysis.resolveAddress(ipaddr)

                if len(resolved) > 0:
                    tmp += f'\t     Value    :    {self.logger.colored(ipaddr, "green")}\n\t     resolved :    {self.logger.colored(resolved, "magenta")}\n\n'
                else:
                    tmp += f'\t     Value    :    {self.logger.colored(ipaddr, "green")}\n\n'

        if len(tmp) > 0:
            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result,
            'description' : '',
        }

    def testXIronPortRemoteIP(self):
        (num, header, value) = self.getHeader('X-IronPort-RemoteIP')
        if num == -1: return []

        result = f'- Cisco IronPort observed following IP of the connecting Client: '
        self.addSecurityAppliance('Cisco IronPort')
        return self._originatingIPTest(result, '', num, header, value)

    def testXSESOutgoing(self):
        (num, header, value) = self.getHeader('X-SES-Outgoing')
        if num == -1: return []

        result = f'- E-Mail sent through Amazon SES. Outgoing: \n\n'
        vals = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').split('-')

        result += f'\t- Date: {vals[0]}'

        return self._originatingIPTest(result, '', num, header, vals[1])

    def _originatingIPTest(self, topicLine, description, num, header, value):
        result = ''

        if '[' == value[0] and value[-1] == ']':
            value = value[1:-1]

        resolved = SMTPHeadersAnalysis.resolveAddress(value)

        result += topicLine

        if len(resolved) > 0:
            result += f'\n\t- {self.logger.colored(value, "red")}\n\t\t- resolved: {resolved}\n'
        else:
            result += f'\n\t- {self.logger.colored(value, "red")}\n\t\t- not resolveable\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testSubjecThreadTopic(self):
        (num1, header1, value1) = self.getHeader('Subject')
        (num2, header2, value2) = self.getHeader('Thread-Topic')
        if num1 == -1 or num2 == -1: return []

        if value1.lower().strip() == value2.lower().strip(): return []

        result = f'- Subject and Thread-Topic headers differ! Possibly {self.logger.colored("target changed Subject","red")} to reflect External E-mail!\n'

        v1 = value1
        v2 = value2

        m1 = re.search(r'\=\?[a-z0-9\-]+\?Q\?', v1, re.I)
        if m1:
            v1d = emailheader.decode_header(value)[0][0]
            if type(v1d) == bytes:
                v1d = v1d.decode(errors='ignore')
            v1 = v1d

        m2 = re.search(r'\=\?[a-z0-9\-]+\?Q\?', v2, re.I)
        if m2:
            v2d = emailheader.decode_header(value)[0][0]
            if type(v2d) == bytes:
                v2d = v2d.decode(errors='ignore')
            v2 = v2d

        result += f'\t- Subject:      {self.logger.colored(v1, "green")}\n'
        result += f'\t- Thread-Topic: {self.logger.colored(v2, "magenta")}\n'

        return {
            'header' : f'{header1}, {header2}',
            'value': f'\n{header1}:\n\t{value1}\n\n    {header2}:\n\t{value2}',
            'analysis' : result,
            'description' : '',
        }

    def testXSeaSpam(self):
        (num, header, value) = self.getHeader('X-SEA-Spam')
        if num == -1: return []

        result = f'- Sophos Email Appliance Spam report:\n'
        self.addSecurityAppliance('Sophos Email Appliance (PureMessage)')
        report = {}
        value = SMTPHeadersAnalysis.flattenLine(value)

        for match in re.finditer(r"(\w+)=(?!')([^,]+)\b,?", value, re.I):
            key = match.group(1)
            val = match.group(2)

            if not key: key = ''
            if not val: val = ''

            if len(key.strip()) == 0: continue
            report[key] = val.strip()

        for match in re.finditer(r"(\w+)='([^']+)'", value, re.I):
            key = match.group(1)
            val = match.group(2)

            if not key: key = ''
            if not val: val = ''

            if len(key.strip()) == 0: continue
            report[key] = [x.strip() for x in val.strip().split(',') if len(x.strip()) > 0]


        for key, val in report.items():
            k = self.logger.colored(key, 'cyan')

            if key.lower() in SMTPHeadersAnalysis.SEA_Spam_Fields.keys():
                result += f'\n\t- {k}:     {SMTPHeadersAnalysis.SEA_Spam_Fields[key.lower()]}\n'
            else:
                result += f'\n\t- {k}: \n'

            if key.lower() == 'report':
                result = result[:-1]
                result += f'. Matched {self.logger.colored(len(val), "yellow")} rules.\n\n'

                for rule in val:
                    if len(rule.strip() ) == 0: continue
                    num = 1
                    num2 = 0

                    if ' ' in rule:
                        rulen, num = rule.split(' ')
                        try:
                            num2 = float(num)
                        except:
                            pass
                    else:
                        rulen = rule

                    col = 'white'

                    if num2 > 0:
                        col = 'yellow'

                    if num2 > 0.5:
                        col = 'red'

                    num = self.logger.colored(num, col)
                    rulen = self.logger.colored(rulen, col)

                    result += f'\t\t- Probability: {num}\tRule: {rulen}\n'

            elif key.lower() == 'gauge':
                leng = len(val)
                numX = val.lower().count('x')
                numI = val.lower().count('i')
                others = leng - numX - numI

                probX = (float(numX) / leng) * 100.0
                probI = (float(numI) / leng) * 100.0
                probOthers = (float(others) / leng) * 100.0

                result += f'\n\t        - Value:      {self.logger.colored(val, "yellow")}\n'
                result += f'\t        - Total length:     {leng}\n'
                result += f'\t        - Number of X:      {numX}   ({probX:.02}%)\n'
                result += f'\t        - Number of I:      {numI}   ({probI:.02}%)\n'
                result += f'\t        - Number of others: {others}   ({probOthers:.02}%)\n'

            elif type(val) == list or type(val) == tuple:
                result += f'\t     Contains {self.logger.colored(len(val), "yellow")} elements.\n'
                for rule in val:
                    if len(rule.strip()) == 0: continue
                    result += f'\t    - {rule}\n'

            else:
                result += f'\t     {val}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }


    def testSpamDiagnosticMetadata(self):
        (num, header, value) = self.getHeader('SpamDiagnosticMetadata')
        if num == -1: return []

        result = f'- SpamDiagnosticMetadata: Antispam stamps in Exchange Server 2016.\n'
        self.addSecurityAppliance('Exchange Server 2016 Anti-Spam')

        if value.strip() in SMTPHeadersAnalysis.Spam_Diagnostics_Metadata.keys():
            result += f'     {value}: ' + SMTPHeadersAnalysis.Spam_Diagnostics_Metadata[value.strip()] + '\n'
        else:
            result += f'     {value}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testIronPortHdrOrdr(self):
        (num, header, value) = self.getHeader('IronPort-HdrOrdr')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        
        if self.decode_all:
            dumped = SMTPHeadersAnalysis.hexdump(SMTPHeadersAnalysis.safeBase64Decode(value))

            result = f'- Cisco IronPort Data encrypted blob:\n\n'
            result += dumped + '\n'

        else:
            result = f'- Cisco IronPort Data encrypted blob. Use --decode-all to print its hexdump.'
        
        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testIronPortData(self):
        (num, header, value) = self.getHeader('IronPort-Data')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')

        if self.decode_all:
            dumped = SMTPHeadersAnalysis.hexdump(SMTPHeadersAnalysis.safeBase64Decode(value))

            result = f'- Cisco IronPort Data encrypted blob:\n\n'
            result += dumped + '\n'

        else:
            result = f'- Cisco IronPort Data encrypted blob. Use --decode-all to print its hexdump.'        

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXIronPortSenderGroup(self):
        (num, header, value) = self.getHeader('X-IronPort-SenderGroup')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        return self._parseCiscoPolicy('\n- Cisco\'s Email Security Appliance (ESA) applied following Mail Flow policy to this e-mails SenderGroup:\n', '', num, header, value)

    def testXIronPortMailFlowPolicy(self):
        (num, header, value) = self.getHeader('X-IronPort-MailFlowPolicy')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        return self._parseCiscoPolicy(
            '\n- Cisco\'s Email Security Appliance (ESA) applied following Mail Flow policy to this e-mail:\n', 
            '''
A mail flow policy allows you to control or limit the flow of email messages from a sender to the listener during the SMTP conversation. 
You control SMTP conversations by defining the following types of parameters in the mail flow policy.

Src: https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118179-configure-esa-00.html
''', 
            num, header, value)

    def testXPolicy(self):
        (num, header, value) = self.getHeader('X-Policy')
        if num == -1: return []

        if value.strip().upper() in SMTPHeadersAnalysis.Cisco_Predefined_MailFlow_Policies.keys():
            self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
            return self._parseCiscoPolicy('\n- Cisco\'s Email Security Appliance (ESA) applied following Mail Flow policy to this e-mail:\n', '', num, header, value)

        else:
            result = '\n- Mail systems applied following policy to this message:\n'
            result += f'\n\t- {value}\n'

            return {
                'header' : header,
                'value': value,
                'analysis' : result,
            'description' : '',
            }

    def _parseCiscoPolicy(self, topicLine, description, num, header, value):
        result = ''

        result += '\n' + topicLine

        k = value.strip().upper()
        k2 = self.logger.colored(k, "yellow")

        if k in SMTPHeadersAnalysis.Cisco_Predefined_MailFlow_Policies.keys():
            result += f'\t     {k2}: ' + SMTPHeadersAnalysis.Cisco_Predefined_MailFlow_Policies[k] + '\n'
        else:
            result += f'\t     {k2}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description
        }

    def testXIronPortReputation(self):
        (num, header, value) = self.getHeader('X-IronPort-Reputation')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        topicLine = f'\n\n- Cisco SenderBase Reputation Service result:\n'
        return self._parseCiscoSBRS(topicLine, '', num, header, value)

    def testXSBRS(self):
        (num, header, value) = self.getHeader('X-SBRS')
        if num == -1: return []

        topicLine = f'\n\n- Cisco SenderBase Reputation Service result (custom header set):\n'
        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        return self._parseCiscoSBRS(topicLine, '', num, header, value)


    def _parseCiscoSBRS(self, topicLine, description, num, header, value):
        result = ''

        if not description or len(description) == 0:
            description = '''
The SenderBase Reputation Score (SBRS) is a numeric value assigned to an IP address based on information
from the SenderBase Reputation Service. The SenderBase Reputation Service aggregates data from over 25
public blocked lists and open proxy lists, and combines this data with global data from SenderBase to assign
a score from -10.0 to +10.0 .

Src: https://www.cisco.com/c/en/us/td/docs/security/esa/esa11-1/user_guide/b_ESA_Admin_Guide_11_1/b_ESA_Admin_Guide_chapter_0101.pdf
'''

        result += topicLine

        num = 0
        try:
            num = float(value.strip())

            if num < 0:
                result += f'\t- Likely {self.logger.colored(f"source of SPAM ({num})", "red")}\n'
            
            elif num >= 0 and num < 5:
                result += f'\t- Likely {self.logger.colored(f"neutral ({num})", "yellow")}\n'

            elif num > 5:
                result += f'\t- Likely {self.logger.colored(f"trustworthy sender ({num})", "green")}\n'

        except:
            result = f'\t- {value} (could not rate that score!)\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testXIronPortAV(self):
        (num, header, value) = self.getHeader('X-IronPort-AV')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        result = f'- Cisco IronPort Anti-Virus interface.\n'
        value = SMTPHeadersAnalysis.flattenLine(value)

        parsed = {}
        for a in value.split(';'):
            k, v = a.split('=')
            k = k.strip()
            v = v.strip()

            if v[0] == '"' and v[-1] == '"':
                v = v[1:-1].replace(' ', '')

            parsed[k] = v

        for k, v in parsed.items():
            result += f'\n\t- ' + SMTPHeadersAnalysis.IronPort_AV[k][0] + ':\n'
            elem = SMTPHeadersAnalysis.IronPort_AV[k][1]

            if k == 'i':
                vs = v.split(',')
                for i in range(len(elem)):
                    result += f'\t\t- {elem[i]}:\t{vs[i]}\n'

            elif k == 'E':
                v0 = self.logger.colored(v, 'red')
                result += f'\t\t- {v0}\n'
                self.securityAppliances.add(f'{v} AV')

            elif k == 'e':
                vs = v.split("'")
                err = 'error'
                if vs[1] in elem.keys():
                    err = elem[vs[1]]

                result += f'\t\t- {err}: {vs[0]}\n'

            elif k == 'v':
                result += f'\t\t- {v}\n'

            elif k == 'd':
                result += f'\t\t- {v}\n'

            elif k == 'a':
                if ':' not in v:
                   result += f'\t\t- {v}\n'
                   continue

                pos = 0
                vs = v.split(':')

                result += f'\t\t- {vs[0]}\n\n'

                _map = SMTPHeadersAnalysis.IronPort_AV[k][1]['_map']
                action = _map[':']

                result += f'\t\t- {action} section:\n'

                while pos < len(vs[1]):
                    c = vs[1][pos]

                    if c in _map.keys():
                        action = _map[c]
                        result += f'\n\t\t- {action} section:\n'
                        pos += 1

                        if action == 'time':
                            ts = vs[1][pos:]

                            ts2 = ''
                            try:
                                ts2 = datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                pass

                            result += f'\t\t\t\t{ts}, {ts2}\n'
                            break

                        continue

                    if c in SMTPHeadersAnalysis.IronPort_AV[k][1][action].keys():
                        h = SMTPHeadersAnalysis.IronPort_AV[k][1][action][c]
                        result += f'\t\t\t- {c}: {h}\n'
                    else:
                        result += f'\t\t\t- {c}\n' 

                    pos += 1          

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXIronPortSpamFiltered(self):
        (num, header, value) = self.getHeader('X-IronPort-Anti-Spam-Filtered')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        if value.strip().strip() == 'true':
            result = f'- Cisco IronPort Anti-Spam rules {self.logger.colored("marked this message SPAM", "red")}.'
        else:
            result = f'- Cisco IronPort Anti-Spam rules considered this message CLEAN.'

        result += f' Value: {value}'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXIronPortSpamResult(self):
        (num, header, value) = self.getHeader('X-IronPort-Anti-Spam-Result')
        if num == -1: return []

        self.addSecurityAppliance('Cisco IronPort / Email Security Appliance (ESA)')
        if self.decode_all:
            dumped = SMTPHeadersAnalysis.hexdump(SMTPHeadersAnalysis.safeBase64Decode(value))

            result = f'- Cisco IronPort Anti-Spam result encrypted blob:\n\n'
            result += dumped + '\n'

        else:
            result = f'- Cisco IronPort Anti-Spam result encrypted blob. Use --decode-all to print its hexdump.'
        
        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXSpamCheckerVersion(self):
        (num, header, value) = self.getHeader('X-Spam-Checker-Version')
        if num == -1: return []

        self.addSecurityAppliance('SpamAssassin')
        result = f'- SpamAssassin version.'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testOvhSpamScore(self):
        (num, header, value) = self.getHeader('X-VR-SPAMSCORE')
        if num == -1: return []

        result = f'- OVH considered this message as SPAM and attached following Spam '
        self.addSecurityAppliance('OVH Anti-Spam')
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')
        result += f'Score: {self.logger.colored(value.strip(), "red")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testOvhSpamReason(self):
        (num, header, value) = self.getHeader('X-Ovh-Spam-Reason')
        if num == -1: return []

        self.addSecurityAppliance('OVH Anti-Spam')
        result = self.logger.colored(f'- OVH considered this message as SPAM', 'red') + ' and attached following information:\n'
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')
        tmp = ''

        for part in value.split(';'):
            part = part.strip()
            tmp += f'\t- {part}\n'

        result += tmp + '\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testSpamCause(self):
        (num, header, value) = self.getHeader('X-VR-SPAMCAUSE')
        if num == -1: return []

        result = ''
        self.addSecurityAppliance('OVH Anti-Spam')
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')

        decoded = SMTPHeadersAnalysis.decodeSpamcause(value)

        if SMTPHeadersAnalysis.printable(decoded):
            result += f'- SPAMCAUSE contains encoded information about spam reasons:\n'
            tmp = ''

            for part in decoded.split(';'):
                part = part.strip()
                tmp += f'\t- {part}\n'

            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testMSFBL(self):
        (num, header, value) = self.getHeader('X-MSFBL')
        if num == -1: return []

        parts = value.split('|')
        result = ''

        for p in parts:
            if p.startswith('eyJ'):
                decoded = base64.b64decode(p)
                if SMTPHeadersAnalysis.printable(decoded):
                    result += f'\t- Headers contained Feedback Loop object used by marketing systems to offer ISPs way to notify the sender that recipient marked that e-mail as Junk/Spam.\n'
                    result += '\n' + json.dumps(json.loads(decoded), indent=4) + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testInterestingHeaders(self):
        return self._testListRelatedHeaders(
            'Other Interesting SMTP headers that were not processed', 
            SMTPHeadersAnalysis.Interesting_Headers
        )

    def testSpamRelatedHeaders(self):
        return self._testListRelatedHeaders(
            'Other Spam related SMTP headers that were not processed', 
            SMTPHeadersAnalysis.Header_Keywords_That_May_Contain_Spam_Info
        )

    def testUnusualHeaders(self):
        result = ''
        num0 = 0
        tmp = ''

        if not self.includeUnusual:
            return []

        shown = set()
        handled = [x.lower() for x in SMTPHeadersAnalysis.Handled_Spam_Headers]

        for num, header, value in self.headers:
            value = SMTPHeadersAnalysis.flattenLine(value)

            if header.lower() in shown or header.lower() in handled: 
                continue

            skip = False
            for rex in SMTPHeadersAnalysis.Usual_SMTP_Headers:
                if re.match(rex, header, re.I):
                    skip = True
                    break

            if skip:
                continue

            shown.add(header.lower())

            num0 += 1

            h = self.logger.colored(header, 'yellow')
            v = self.colorizeKeywords(value[:60])

            if len(value) > 60:
                v += ' (...)'

            c = ' ' * (30 - len(header))
            if len(header) > 30: c = ''
            tmp += f'\t- {h}{c}: {v}\n\n'

        if len(tmp) > 0:
            result += f'\n- This script is aware of {len(SMTPHeadersAnalysis.Usual_SMTP_Headers)} typical SMTP Headers.\n'
            result += f'\n- Below {num0} headers are considered unusual:\n\n'

            result += tmp

        if len(result) == 0:
            return []

        return {
            'header' : '',
            'value': '',
            'analysis' : result,
            'description' : 'This script knows only limited number of SMTP headers making output of this test overly verbose.',
        }

    def testSpamAssassinSpamAlikeLevels(self):
        result = ''
        tmp = ''
        num0 = 0
        headers = []
        values = []

        shown = set()
        handled = [x.lower() for x in SMTPHeadersAnalysis.Handled_Spam_Headers]

        for num, header, value in self.headers:
            value = SMTPHeadersAnalysis.flattenLine(value)

            if header in shown or header in handled: 
                continue

            if re.match(r'\s*\*{1,6}\s*', value):
                num0 += 1

                out = self._parseAsteriskRiskScore('', '', num, header, value)
                headers.append(header)
                values.append(value)
                SMTPHeadersAnalysis.Handled_Spam_Headers.append(header.lower())

                tmp += f'\t({num0:02}) {self.logger.colored("Header", "magenta")}:   {header}\n'
                tmp += out['analysis']
                shown.add(header)

        if len(tmp) > 0:
            self.addSecurityAppliance('SpamAssassin alike')
            result = '\n- Found SpamAssassin like headers that might indicate Spam Risk score:\n'
            result += tmp + '\n'

        if len(result) == 0:
            return []

        if len(headers) > 1: headers[0] = '\t' + headers[0]
        if len(values) > 1: values[0] = '\t' + values[0]

        return {
            'header' : '\n\t'.join(headers),
            'value': '\n\t'.join(values),
            'analysis' : result,
            'description' : '',
        }

    def _testListRelatedHeaders(self, msg, listOfValues):
        result = ''
        tmp = ''
        num0 = 0
        shown = set()

        handled = [x.lower() for x in SMTPHeadersAnalysis.Handled_Spam_Headers]

        for num, header, value in self.headers:
            value = SMTPHeadersAnalysis.flattenLine(value)

            if header in shown or header.lower() in handled: 
                continue

            for dodgy in listOfValues:
                if header in shown: 
                    break

                if dodgy in header.lower() and header.lower():
                    num0 += 1
                    hhh = re.sub(r'(' + re.escape(dodgy) + r')', self.logger.colored(r'\1', 'red'), header, flags=re.I)

                    tmp += f'\t({num0:02}) {self.logger.colored("Header", "magenta")}:   {hhh}\n'
                    tmp += f'\t     Keyword:  {dodgy}\n'
                    tmp += f'\t     Value:    {value[:120]}\n\n'
                    shown.add(header)
                    SMTPHeadersAnalysis.Handled_Spam_Headers.append(header.lower())
                    break

                elif dodgy in value.lower() and header.lower():
                    num0 += 1
                    hhh = header
                    tmp += f'\t({num0:02}) Header:   {hhh}\n'

                    pos = value.lower().find(dodgy)
                    ctx = re.sub(r'(' + re.escape(dodgy) + r')', self.logger.colored(r'\1', 'red'), value, flags=re.I)

                    if len(ctx) > 1024:
                        a = pos-40
                        b = -10 + pos + len(dodgy) + 30
                        
                        if a < 0: a = 0
                        if b > len(ctx): b = len(ctx)

                        ctx = value[a:b]

                    ctx = ctx.strip()

                    tmp += f'\t     Keyword:  {dodgy}\n'
                    tmp += f'\t     {self.logger.colored("Value", "magenta")}:\n\n{ctx}\n\n'
                    shown.add(header)
                    SMTPHeadersAnalysis.Handled_Spam_Headers.append(header.lower())
                    break

        if len(tmp) > 0:
            result = f'- {msg}:\n\n'
            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result,
            'description' : '',
        }

    def testSpamAssassinSpamStatus(self):
        (num, header, value) = self.getHeader('X-Spam-Status')
        if num == -1: return []

        self.addSecurityAppliance('SpamAssassin')
        result = '- SpamAssassin spam report\n\n'
        return self._parseSpamAssassinStatus(result, '', num, header, value, SMTPHeadersAnalysis.Barracuda_Score_Thresholds)

    def _parseSpamAssassinStatus(self, topic, description, num, header, value, thresholds):        
        parsed = {}
        result = topic
        col = 'green'
        _result = value.strip().split(',')[0]
        parsed['_result'] = _result

        if parsed['_result'].lower() == 'yes':
            col = 'red'
        
        parsed['_result'] = self.logger.colored(value.strip().split(',')[0].upper(), col)

        pos = len(_result)+2
        extranum = 0
        stop = False

        while pos < len(value):
            pose = value.find('=', pos)
            if pose == -1: break

            k = value[pos:pose]
            
            pos2 = len(k) - 1
            while pos2 >= 0:
                if k[pos2] == ' ':
                    parsed[f'extra{extranum}'] = k[:pos2]
                    k = k[pos2+1:]
                    extranum += 1
                    break
                pos2 -= 1

            l = len(k) - len(k.lstrip())
            if l > 0:
                k = k.strip()
                pos += l

            if k == 'tests':
                v0 = value[pose+1:].replace('\t', ' ').replace('\n', ' ')
                m = re.search(r'\s+([a-z_]+\=)', v0)

                if m:
                    pos0 = value.find(m.group(1), pose+1)
                    v = value[pose+1:pos0].replace(' ', '').replace('\n', '').split(',')
                    pos = pos0
                else:
                    v = v0.replace(' ', '').replace('\n', '').split(',')
                    stop = True
            else:
                sp = value.find(' ', pose)
                if sp == -1: break

                v = value[pose+1:sp]
                pos = sp + 1

            parsed[k] = v
            if stop:
                break

        keys = [x.lower() for x in parsed.keys()]

        if 'tag_level' in keys:
            level = float(parsed[list(parsed.keys())[keys.index('tag_level')]])
            thresholds[0][1] = level - 0.01
            thresholds[1][0] = level

        if 'quarantine_level' in keys:
            level = float(parsed[list(parsed.keys())[keys.index('quarantine_level')]])
            thresholds[1][1] = level - 0.01
            thresholds[2][0] = level

        if 'kill_level' in keys:
            level = float(parsed[list(parsed.keys())[keys.index('kill_level')]])
            thresholds[2][1] = level - 0.01
            thresholds[3][0] = level

        for k, v in parsed.items():
            if k in SMTPHeadersAnalysis.SpamAssassin_Spam_Status[1].keys():
                k0 = self.logger.colored(k, 'magenta')
                result += f'\t- {k0}: ' + SMTPHeadersAnalysis.SpamAssassin_Spam_Status[1][k] + '\n'

            else:
                k0 = self.logger.colored(k, 'magenta')
                result += f'\t- {k0}: \n'

            if k.lower() == 'score':
                score = self._parseThresholdsBasedScore(v, thresholds)
                if score != '':
                    v += f' - {score}'

            if type(v) == str:
                result += f'\t\t- {v}\n'
            else:
                result += f'\t\t- elements {len(v)}:\n'
                for a in v:
                    result += f'\t\t\t- {a.strip()}\n'

            result += '\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testDomainImpersonation(self):
        (num, header, value) = self.getHeader('From')
        if num == -1: return []

        result = ''
        m = re.search(r'<?([^<@\s]+)@([^\s]+)>?', value)
        domain = ''

        if not m:
            return []

        if m and len(self.received_path) < 3:
            return []

        if len(m.groups()) < 2:
            return []

        username = m.group(1).replace('<', '')
        domain = m.group(2).replace('>', '')

        email = f'{username}@{domain}'

        firstHop = self.received_path[1]
        
        mailDomainAddr = ''
        revMailDomain = ''
        revFirstSenderDomain = firstHop['host2']
        firstSenderAddr = ''

        try:
            mailDomainAddr = SMTPHeadersAnalysis.gethostbyname(domain)
            revMailDomain = SMTPHeadersAnalysis.gethostbyaddr(mailDomainAddr)

            if(len(firstHop['ip'])) > 0 and len(revFirstSenderDomain) == 0:
                revFirstSenderDomain = SMTPHeadersAnalysis.gethostbyaddr(firstHop['ip'])

            if(len(firstHop['host'])) > 0:
                firstSenderAddr = SMTPHeadersAnalysis.gethostbyname(firstHop['host'])
                if len(revFirstSenderDomain) == 0:
                    revFirstSenderDomain = SMTPHeadersAnalysis.gethostbyaddr(firstSenderAddr)
        except: 
            pass

        senderDomain = SMTPHeadersAnalysis.extractDomain(revMailDomain)
        firstHopDomain1 = SMTPHeadersAnalysis.extractDomain(revFirstSenderDomain)

        if len(senderDomain) == 0: senderDomain = domain
        if len(firstHopDomain1) == 0: firstHopDomain1 = firstHop["host"]

        senderDomain = senderDomain.replace('<','').replace('>','').strip()
        firstHopDomain1 = firstHopDomain1.replace('<','').replace('>','').strip()

        result += f'\t- Mail From: <{email}>\n\n'
        result += f'\t- Mail Domain: {domain}\n'
        result += f'\t               --> resolves to: {mailDomainAddr}\n'
        result += f'\t                   --> reverse-DNS resolves to: {revMailDomain}\n'
        result += f'\t                       (sender\'s domain: {self.logger.colored(senderDomain, "cyan")})\n\n'

        result += f'\t- First Hop:   {firstHop["host"]} ({firstHop["ip"]})\n'
        result += f'\t               --> resolves to: {firstSenderAddr}\n'
        result += f'\t                   --> reverse-DNS resolves to: {revFirstSenderDomain}\n'
        result += f'\t                       (first hop\'s domain: {self.logger.colored(firstHopDomain1, "cyan")})\n\n'

        if firstHopDomain1.lower() != senderDomain.lower():
            response = []
            try:
                if domain.endswith('.'): 
                    domain = domain[:-1]
                response = dns.resolver.resolve(domain, 'TXT')

            except dns.resolver.NoAnswer as e:
                response = []

            except dns.resolver.NoNameservers as e:
                response = []

            except AttributeError as e:
                response = []

            except Exception as e:
                response = []

            spf = False

            for answer in response:
                txt = str(answer)
                if 'v=spf' in txt:
                    result += f'- Domain SPF: {txt[:64]}\n'

                    for _domain in re.findall(r'([a-z0-9_\.-]+\.[a-z]{2,})', txt):
                        _domain1 = SMTPHeadersAnalysis.extractDomain(_domain)

                        if _domain1.lower() == firstHopDomain1:
                            result += self.logger.colored(f'\n\t- [+] First Hop ({firstHopDomain1}) is authorized to send e-mails on behalf of ({domain}) due to SPF records.\n', 'yellow')
                            result += '\t- So I\'m not sure if there was Domain Impersonation or not, but my best guess is negative.\n'
                            spf = True
                            break

                if spf:
                    break

            if not spf:
                result += '\n- (this test is very false-positive prone, below results can be inaccurate)'
                result += self.logger.colored('\n\n- WARNING! Potential Domain Impersonation!\n', 'red')
                result += f'\t- Mail\'s domain should resolve to: \t{self.logger.colored(senderDomain, "green")}\n'
                result += f'\t- But instead first hop resolved to:\t{self.logger.colored(firstHopDomain1, "red")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testSpamAssassinSpamFlag(self):
        (num, header, value) = self.getHeader('X-Spam-Flag')
        if num == -1: return []

        self.addSecurityAppliance('SpamAssassin')

        if value.strip().lower() == 'yes':
            result = self.logger.colored(f'- SpamAssassin marked this message as SPAM:\n', 'red')
            result += f'\t- ' + self.logger.colored(value, 'red') + '\n'
        else:
            result = self.logger.colored(f'- SpamAssassin did not mark this message as spam:\n', 'green')
            result += f'\t- ' + self.logger.colored(value, 'green') + '\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def _parseAsteriskRiskScore(self, topicLine, description, num, header, value):
        desc = ''

        result = topicLine
        value = value.strip()
        val = self.logger.colored(value, 'yellow')

        if len(value) <= 6:
            if value in SMTPHeadersAnalysis.Aterisk_Risk_Score.keys():
                desc = f' ({SMTPHeadersAnalysis.Aterisk_Risk_Score[value]})'

            a = len(value)
            b = 6
            result += f'\t- ({a}/{b})    {val}   {desc}\n\n'

        else:
            result += f'\t- {val}\n\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testSpamAssassinSpamLevel(self):
        (num, header, value) = self.getHeader('X-Spam-Level')
        if num == -1: return []
        self.addSecurityAppliance('SpamAssassin')
        return self._parseAsteriskRiskScore('- SpamAssassin assigned following spam level to this message:\n', '', num, header, value)

    def testSpamAssassinSpamReport(self):
        (num, header, value) = self.getHeader('X-Spam-Report')
        if num == -1: return []

        self.addSecurityAppliance('SpamAssassin')
        if len(value.strip()) > 0:
            result = f'- SpamAssassin assigned following spam report to this message:\n'
            tmp = ''

            for line in value.split('\n'):
                if line.strip().startswith('* '):
                    line = line.strip()[2:]
                    result += f'- {line}\n'

            result += tmp + '\n'

            return {
                'header' : header,
                'value': value,
                'analysis' : result,
                'description' : '',
            }

        return []

    def testATPMessageProperties(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-AtpMessageProperties')
        if num == -1: return []

        props = value.split('|')
        self.addSecurityAppliance('MS Defender Advanced Threat Protection')
        result = '- MS Defender Advanced Threat Protection enabled following protections on this message:\n'

        for prop in props:
            if prop in SMTPHeadersAnalysis.ATP_Message_Properties.keys():
                result += f'\t- ' + self.logger.colored(SMTPHeadersAnalysis.ATP_Message_Properties[prop], 'magenta') + '\n'
                self.addSecurityAppliance('MS Defender for Office365 - ' + SMTPHeadersAnalysis.ATP_Message_Properties[prop])

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXAmpResult(self):
        (num, header, value) = self.getHeader('X-Amp-Result')
        if num == -1: return []

        self.addSecurityAppliance('Cisco Advanced Malware Protection (AMP)')
        result = '- Cisco Meraki Advanced Malware Protection (AMP) sandbox marked this message as:\n'
        val = value.strip()
        k = value.strip().upper()

        if k in SMTPHeadersAnalysis.AMP_Results.keys():
            val = f'\t- {k}: {SMTPHeadersAnalysis.AMP_Results[k]}\n'
        else:
            result += f'\t- {val}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXIPSpamVerdict(self):
        (num, header, value) = self.getHeader('X-IP-Spam-Verdict')
        if num == -1: return []

        self.addSecurityAppliance('SpamAssassin')
        result = '- An old SpamAssassin SPAM verdict header:\n'

        col = 'cyan'
        if 'spam' in value.lower():
            col = "red"
        
        result += '\t- ' + self.logger.colored(value.strip(), col)

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def parseReceived(self, received, numReceived):
        obj = {
            'host' : '',
            'host2' : '',
            'ip' : '',
            'timestamp' : '',
            'ver' : '',
            'with' : '',
            'extra' : [],
            'num' : numReceived,
        }

        keys = (
            'from',
            'by',
            'via',
            'with',
            'id',
            'for',
        )

        found = set()

        parsed = {}

        pos = 0
        lastkey = ''
        posOfKey = 0
        extrapos = 0

        if not received.lower().strip().startswith('from'):
            received = 'from ' + received

        paren = 0
        while pos < len(received):
            keynow = ''

            if received[pos] == '(':
                paren += 1
                pos += 1
                continue

            elif received[pos] == ')':
                paren -= 1
                pos += 1
                continue

            if paren > 0 or received[pos] in string.whitespace:
                pos += 1
                continue

            for key in keys:
                if key in found: continue
                tmp = False
                if pos == 0: tmp = True
                else: tmp = (received[pos-1] in string.whitespace)

                if received[pos:].lower().startswith(key + ' ') and tmp:
                    if lastkey != '':
                        parsed[lastkey] = received[posOfKey+len(lastkey)+1:pos].strip()

                    lastkey = keynow = key
                    posOfKey = pos
                    found.add(key)
                    pos += len(key)
                    break

            pos += 1

        if lastkey not in parsed.keys():
            parsed[lastkey] = received[posOfKey+len(lastkey)+1:].strip()

            if ';' in parsed[lastkey]:
                pos = parsed[lastkey].find(';')
                parsed[lastkey] = parsed[lastkey][:pos]

        obj['parsed'] = parsed

        if 'from' not in parsed.keys():
            return {}

        obj['host'] = ''
        obj['ip'] = ''
        obj['host2'] = ''

        match = re.search(
            r'(?P<host>[^\s]+)\s*(?:\((?P<host2>[^\s]+)\.?(?:\s*\[(?P<ip>[^]]+)\])?\))?', 
            parsed['from'], 
            re.I
        )

        if match:
            obj['host'] = match.group('host')
            obj['ip'] = match.group('ip')
            obj['host2'] = match.group('host2')

            if not obj['ip']: obj['ip'] = ''
            if not obj['host']: obj['host'] = ''
            if not obj['host2']: 
                obj['host2'] = ''
            else:
                if obj['host2'].endswith('.'): 
                    obj['host2'] = obj['host2'][:-1]

            if obj['host'][0] == '[' and obj['host'][-1] == ']':
                obj['ip'] = obj['host'][1:-1]
                obj['host'] = ''

            obj['host2'] = obj['host2'].lower().replace('ehlo=', 'helo=')

            if 'helo=' in obj['host2'].lower():
                obj['host'] = obj['host2'][obj['host2'].lower().find('helo=')+5:]
                obj['host2'] = ''

            if obj['host'] == '' and obj['ip'] != '':
                try:
                    res = SMTPHeadersAnalysis.gethostbyaddr(obj['ip'])
                    if len(res) > 0:
                        obj['host'] = res
                except:
                    pass

            if len(obj['host2']) > 0:
                match = re.match(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', obj['host2'])
                if obj['ip'] == None or len(obj['ip']) == 0 and match:
                    obj['ip'] = match.group(1)
                    obj['host2'] = ''

            if len(obj['host2']) == 0:
                if obj['ip'] != None and len(obj['ip']) > 0:
                    try:
                        res = SMTPHeadersAnalysis.gethostbyaddr(obj['ip'])
                        if len(res) > 0:
                            obj['host2'] = res
                    except:
                        obj['host2'] = self.logger.colored('NXDomain', 'red')

            if extrapos == 0:
                a = received.find(obj['host']) + len(obj['host'])
                b = received.find(obj['host2']) + len(obj['host2'])
                c = received.find(obj['ip']) + len(obj['ip'])

                extrapos = max(a, b, c)
        else:
            return {}

        if 'id' in parsed.keys():
            ver = parsed['id'].strip()
            obj['ver'] = ver

        pos = received.find(';')
        if pos != -1:
            ts = received[pos+1:].strip()
            obj['timestamp'] = str(parser.parse(ts).astimezone(tzutc()))

        for m in re.finditer(r'(?<!\+\d{4}\s)\(([^\)]+)\)', received[extrapos:], re.I):
            v = m.group(1)

            match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', v.strip())
            if match:
                skip = False
                for k1, v1 in obj['parsed'].items():
                    if type(v1) != str: continue
                    if match.group(1) in v1: 
                        skip = True
                        break
                if skip:
                    continue

            if v in SMTPHeadersAnalysis.Time_Zone_Acronyms:
                continue

            obj['extra'].append(v)

        tldextracted = tldextract.extract(obj['host'])
        hostnameExposed = False

        if (len(tldextracted.domain) > 0 and len(tldextracted.suffix) == 0) \
            or len(tldextracted.suffix) > 0 and len(tldextracted.domain) == 0: 
            hostnameExposed = True

        elif len(tldextracted.domain) > 0 and len(tldextracted.suffix) > 0 and not options['dont_resolve']: 
            res = SMTPHeadersAnalysis.gethostbyname(f'{tldextracted.domain}.{tldextracted.suffix}')
            hostnameExposed = res == ''

        if hostnameExposed:
            obj['extra'].append(f'Hostname exposed: {self.logger.colored(obj["host"], "red")}')
            self.mtaHostnamesExposed[obj['host']] = (numReceived, 'Received', received)

        obj['_raw'] = received

        for k in obj.keys():
            if type(obj[k]) == str:
                obj[k] = obj[k].strip()

        for k in ['with', 'by', 'id', 'via']:
            if k in parsed.keys():
                ver = parsed[k].strip()
                if ver.find(' (') != -1:
                    ver = ver[:ver.find(' (')]

                obj[k] = ver

        self.logger.dbg('Parsed Received header:\n' + str(json.dumps(obj, indent=4)))

        return obj

    def colorizeKeywords(self, val):
        for item in SMTPHeadersAnalysis.Interesting_Headers + SMTPHeadersAnalysis.Header_Keywords_That_May_Contain_Spam_Info:
            val0 = val
            val = re.sub(r'(' + re.escape(item) + r')', self.logger.colored(r'\1', 'red'), val, flags=re.I)

            if item in SMTPHeadersAnalysis.Header_Keywords_That_May_Contain_Spam_Info:
                self.securityAppliances.add(val)

        return val

    def testReceived(self):
        received = []
        SMTPHeadersAnalysis.Handled_Spam_Headers.append('received')

        for i in range(len(self.headers)):
            if self.headers[i][1].lower() == 'received':
                received.append(self.headers[i])

        result = ''
        path = []

        (n1, h1, v1) = self.getHeader('From')
        (n2, h2, v2) = self.getHeader('To')

        if len(received) == 0:
            return []

        if n1 != -1:
            path.append({
            'host' : 'From: ' + self.logger.colored(v1, 'green'),
            'host2' : '',
            'timestamp' : None,
            'ip' : '',
            'ver' : '',
            'parsed' : {},
            'extra' : [],
            'num' : 0,
        })

        numReceived = 0
        for i in range(len(received), 0, -1):
            r = received[i - 1][2]
            r = SMTPHeadersAnalysis.flattenLine(r)

            numReceived += 1
            obj = self.parseReceived(r, numReceived)

            if 'ver' in obj.keys() and len(obj['ver']) > 0:
                vers = SMTPHeadersAnalysis.parseExchangeVersion(obj['ver'])
                if vers != None:
                    obj['ver'] = self.logger.colored(str(vers), 'magenta')

            if obj and (obj['ip'] == None or len(obj['ip']) == 0):
                if obj['host'] != None and len(obj['host']) > 0:
                    try:
                        obj['ip'] = SMTPHeadersAnalysis.gethostbyname(obj['host'])
                    except:
                        pass

                if obj['ip'] != None and len(obj['ip']) > 0:
                    match = re.match(r'(?P<host>[^\s]+)\.?\s+\[(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', obj['ip'], re.I)
                    match2 = re.search(r'\[(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', obj['ip'], re.I)

                    if match:
                        obj['host'] = match.group('host')
                        obj['ip'] = match.group('ip')

                    elif match2:
                        obj['ip'] = match2.group(1)

            if len(obj) > 0:
                path.append(obj)

        if n2 != -1:
            path.append({
            'host' : 'To: ' + self.logger.colored(v2, 'green'),
            'host2' : '',
            'ip' : '',
            'timestamp' : None,
            'ver' : '',
            'parsed' : {},
            'extra' : [],
            'num' : len(path) + 1,
        })

        result = '- List of server hops used to deliver message:\n\n'
        iindent = '  '
        indent = '    '
        num = 0

        for i in range(len(path)):
            elem = path[i]

            if len(elem) < 2:
                continue

            num += 1
            s = '-->'
            if i > 0:
                s = '|_>'
            
            if num == 2 or n1 == -1:
                result += iindent + indent * (num+1) + f'{s} ({elem["num"]}) {self.logger.colored(elem["host"], "green")}'
            else:
                result += iindent + indent * (num+1) + f'{s} ({elem["num"]}) {self.logger.colored(elem["host"], "yellow")}'

            if elem['ip'] != None and len(elem['ip']) > 0:
                if elem['ip'][0] == '[' and elem['ip'][-1] == ']':
                    elem['ip'] = elem['ip'][1:-1]

                if num == 2:
                    result += f' ({self.logger.colored(elem["ip"], "green")})\n'
                else:
                    result += f' ({self.logger.colored(elem["ip"], "yellow")})\n'
            else:
                result += '\n'

            if len(elem['host2']) > 0:
                if elem['host2'].endswith('.'):
                    elem['host2'] = self.logger.colored(elem['host2'][:-1], 'yellow')

                if elem['host2'] != elem['host'] and elem['host2'] != elem['ip']:
                    #result += f' (rev: {self.logger.colored(elem["host2"], "yellow")})'
                    result += iindent + indent * (num+3) + 'rev-DNS:  ' + self.logger.colored(elem["host2"], "yellow") + '\n'

            if elem['timestamp'] != None:
                result += iindent + indent * (num+3) + 'time:     ' + elem['timestamp'] + '\n'

            if len(elem['ver']) > 0:
                result += iindent + indent * (num+3) + 'id:       ' + elem['ver'] + '\n'

            for kk, vv in elem['parsed'].items():
                vv = str(vv)
                if len(vv.strip()) == 0: continue

                if kk.lower() not in ['ip', 'host', 'host2', 'id', 'timestamp', 'parsed', 'extra', '_raw', 'from', 'time']:
                    n = 8 - len(kk)
                    if n < 0: n = 0
                    vv2 = vv.replace('<', '').replace('>', '')
                    if kk == 'for' and (vv2 == v1 or vv2 == v2):
                        continue

                    vv = self.colorizeKeywords(vv)
                    result += iindent + indent * (num+3) + kk + ': ' + ' ' * (n) + vv + '\n'

            if 'extra' in elem.keys() and len(elem['extra']) > 0:
                result += iindent + indent * (num+3) + 'extra: \n'
                for vv in elem['extra']:
                    vv0 = self.colorizeKeywords(vv)
                    result += iindent + indent * (num+4) + '- ' + vv0 + '\n'

            result += '\n'

        self.received_path = path

        if 1 not in self.testsToRun:
            return []

        return {
            'header' : 'Received',
            'value': '...',
            'analysis' : result,
            'description' : '',
        }

    def testAntispamReportCFA(self):
        (num, header, value) = self.getHeader('X-Exchange-Antispam-Report-CFA-Test')
        if num == -1: return []

        obj = {
            'header' : header,
            'value' : value,
            'analysis' : '',
            'description' : '',
        }

        result = ''

        obj2 = self._parseAntiSpamReport(num, header, value)
        result += obj2['analysis']

        obj1 = self._parseBulk(num, header, value)
        result += '\n' + obj1['analysis']

        self.addSecurityAppliance('MS ForeFront Anti-Spam')

        obj['analysis'] = result
        return obj

    def testMicrosoftAntiSpam(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam')
        if num == -1: return []

        self.addSecurityAppliance('MS ForeFront Anti-Spam')
        return self._parseBulk(num, header, value)

    def testForefrontAntiSCL(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-Organization-SCL')
        if num == -1: return []

        tmp = self._parseSCLBased(value.strip(), 'SCL', 'Spam Confidence Level', 'spam', SMTPHeadersAnalysis.ForeFront_Spam_Confidence_Levels)

        if len(tmp) == 0:
            return []

        result = tmp + '\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def _parseSCLBased(self, score, key, topic, listname, listelems):
        addscl = False
        tmpfoo = ''
        result = ''

        v = (topic, listname, listelems)

        k = key
        addscl = True
        scl = int(score)
        k0 = self.logger.colored(k, 'magenta')
        tmpfoo += f'- {k0}: {v[0]}: ' + str(scl) + '\n'

        levels = list(v[2].keys())
        levels.sort()

        if scl in levels:
            s = v[2][scl]
            f = self.logger.colored(f'Not {v[1]}', 'green')
            if s[0]:
                f = self.logger.colored(v[1].upper(), 'red')

            tmpfoo += f'\t- {f}: {s[1]}\n'

        else:
            for i in range(len(levels)):
                if scl <= levels[i] and i > 0:
                    s = v[2][levels[i-1]]
                    f = self.logger.colored(f'Not {v[1]}', 'green')
                    if s[0]:
                        f = self.logger.colored(v[1].upper(), 'red')

                    tmpfoo += f'\t- {f}: {s[1]}\n'
                    break
                elif scl <= levels[0]:
                    s = v[2][levels[0]]
                    f = self.logger.colored(f'Not {v[1]}', 'green')
                    if s[0]:
                        f = self.logger.colored(v[1].upper(), 'red')

                    tmpfoo += f'\t- {f}: {s[1]}\n'
                    break

        if addscl:
            result += tmpfoo

        return result

    def _parseBulk(self, num, header, value):
        parsed = {}
        result = ''

        for entry in value.split(';'):
            if(len(entry.strip()) == 0): continue
            k, v = entry.strip().split(':')
            parsed[k] = v

        if 'BCL' in parsed.keys():
            scl = int(parsed['BCL'])
            tmp = ''
            lvl = self.logger.colored(str(scl), 'green')
            if scl > 0:
                lvl = self.logger.colored(str(scl), 'red')

            tmp += f'- {self.logger.colored("BCL", "magenta")}: BULK Confidence Level: ' + lvl + '\n'

            levels = list(SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels.keys())
            levels.sort()

            if scl in levels:
                tmp += '\t- ' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[scl] + '\n'

            else:
                for i in range(len(levels)):
                    if scl <= levels[i] and i > 0:
                        tmp += '\t' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[levels[i-1]] + '\n'
                        break
                    elif scl <= levels[0]:
                        tmp += '\t' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[levels[0]] + '\n'
                        break

            result += tmp

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testForefrontAntiSpamReport(self):
        (num, header, value) = self.getHeader('X-Forefront-Antispam-Report')
        if num == -1: return []

        self.addSecurityAppliance('MS ForeFront Anti-Spam')
        return self._parseAntiSpamReport(num, header, value)

    def testForefrontAntiSpamReportUntrusted(self):
        (num, header, value) = self.getHeader('X-Forefront-Antispam-Report-Untrusted')
        if num == -1: return []

        self.addSecurityAppliance('MS ForeFront Anti-Spam')
        return self._parseAntiSpamReport(num, header, value)

    def testForefrontAntiSpamUntrusted(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam-Untrusted')
        if num == -1: return []

        self.addSecurityAppliance('MS ForeFront Anti-Spam')
        return self._parseAntiSpamReport(num, header, value)
    
    def _parseAntiSpamReport(self, num, header, value):
        parsed = {}
        result = '- Microsoft Office365/Exchange ForeFront Anti-Spam report\n\n'

        for entry in value.split(';'):
            if len(entry.strip()) == 0: continue
            k, v = entry.split(':')
            if k not in parsed.keys():
                parsed[k] = v

        if 'CIP' in parsed.keys():
            res = ''
            if self.resolve:
                resolved = SMTPHeadersAnalysis.resolveAddress(parsed['CIP'])

                result += f'- {self.logger.colored("CIP", "magenta")}: Connecting IP address:\n\t- {self.logger.colored(parsed["CIP"], "yellow")} (resolved: {self.logger.colored(resolved, "magenta")})\n\n'
            else:
                result += f'- {self.logger.colored("CIP", "magenta")}: Connecting IP address:\n\t- {self.logger.colored(parsed["CIP"], "yellow")}\n\n'

        for k, v in parsed.items():
            elem = None

            if k.upper() in SMTPHeadersAnalysis.Forefront_Antispam_Report.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Report[k.upper()]

            elif k in SMTPHeadersAnalysis.Forefront_Antispam_Report.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Report[k]

            if elem:
                vals = v.split(',')
                found = False
                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- {k0}: ' + elem[0] + '\n'

                if type(elem[1]) == dict:
                    for va in vals:
                        if va in elem[1].keys():
                            found = True
                            tmp += f'\t- {va}: {elem[1][va]}\n'

                    if not found and len(v.strip()) > 0:
                        tmp += f'\t- {v}\n'
                        found = True
                
                elif len(v) > 0:
                    found = True
                    tmp += f'\t- {v}\n'

                if found:
                    result += tmp + '\n'

        usedRE = False
        for k in ['SFS', 'RULEID', 'ENG']:
            if k in parsed.keys():
                res = ''
                rules = [x.replace('(', '') for x in parsed[k].split(')')]

                if len(rules) == 1 and len(rules[0].strip()) == 0:
                    rules = []

                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- Message matched {self.logger.colored(str(len(rules)), "yellow")} Anti-Spam rules ({k0}):\n'

                rules.sort()
                for r in rules:
                    if len(r) == 0: continue

                    r2 = f'({r})'
                    if r in SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered.keys():
                        e = SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered[r]
                        tmp += f'\t- {r2: <15} - {self.logger.colored(e, "yellow")}\n'
                        usedRE = True
                    else:
                        tmp += f'\t- {r2}\n'

                result += tmp + '\n'

        if usedRE:
            result += '\tNOTICE:\n'
            result += '\t(Anti-Spam rule explanation can only be considered as a clue, hint rather than a definitive explanation.)\n'
            result += '\t(Rules meaning was established merely in a trial-and-error process by observing SMTP header differences.)\n\n'

        sclpcl = {
            'SCL' : ('Spam Confidence Level', 'spam', SMTPHeadersAnalysis.ForeFront_Spam_Confidence_Levels),
            'PCL' : ('Phishing Confidence Level', 'phishing', SMTPHeadersAnalysis.ForeFront_Phishing_Confidence_Levels),
        }

        addscl = False
        tmpfoo = ''

        for k, v in sclpcl.items():
            if k in parsed.keys():
                addscl = True
                scl = int(parsed[k])
                k0 = self.logger.colored(k, 'magenta')
                tmpfoo += f'- {k0}: {v[0]}: ' + str(scl) + '\n'

                levels = list(v[2].keys())
                levels.sort()

                if scl in levels:
                    s = v[2][scl]
                    f = self.logger.colored(f'Not {v[1]}', 'green')
                    if s[0]:
                        f = self.logger.colored(v[1].upper(), 'red')

                    tmpfoo += f'\t- {f}: {s[1]}\n'

                else:
                    for i in range(len(levels)):
                        if scl <= levels[i] and i > 0:
                            s = v[2][levels[i-1]]
                            f = self.logger.colored(f'Not {v[1]}', 'green')
                            if s[0]:
                                f = self.logger.colored(v[1].upper(), 'red')

                            tmpfoo += f'\t- {f}: {s[1]}\n'
                            break
                        elif scl <= levels[0]:
                            s = v[2][levels[0]]
                            f = self.logger.colored(f'Not {v[1]}', 'green')
                            if s[0]:
                                f = self.logger.colored(v[1].upper(), 'red')

                            tmpfoo += f'\t- {f}: {s[1]}\n'
                            break

        if addscl:
            result += tmpfoo

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testSenderAddress(self):
        headersFound = set()

        senderHeaders = (
            'MAIL FROM',
            'mail-from',
            'Return-Path',
            'X-Env-Sender',
            'From',
            'Sender',
            'X-Apparently-From',
        )

        addresses = []

        for (num, header, value) in self.headers:
            if header.lower() not in [x.lower() for x in senderHeaders]: 
                continue

            headersFound.add(header)

        result = ''
        headers = ''
        values = ''
        num1 = 0

        for header in headersFound:
            (num, hdr, value) = self.getHeader(header)
            if num != -1:
                num1 += 1

                m = re.search(r'([\w\._\+-]+@([\w.-]+\.)+[\w]{2,})', value, re.I)
                if m:
                    value = m.group(1)
                else:
                    value = value.replace('<', '').replace('>', '').replace('\t', '').replace(' ', '').strip()

                headers += f'    - {hdr}\n'
                values += f'    - {value}\n'

                t = self.logger.colored(f"{hdr:20}", "yellow")
                v = self.logger.colored(value, "green")
                addresses.append(value)

                result +=f'\n\t- {t}: {v}'


        if num1 == 0:
            return []

        result = f'\n- Identified sender addresses ({num1}):\n' + result

        if len(addresses) > 0:
            if not addresses.count(addresses[0]) == len(addresses):
                result += self.logger.colored(f'\n\n- WARNING! Not all sender addresses match each other - potential Mail Spoofing!\n', 'red')
                result += '- See here for more info: https://blog.shiraj.com/2020/05/email-spoofing/\n'

        return {
            'header' : '\n'+headers,
            'value': values,
            'analysis' : result,
            'description' : f'Sender\'s address was found in {num1} different SMTP headers.',
        }

    def testFrom(self):
        (num, header, value) = self.getHeader('From')
        if num == -1: return []

        result = ''
        m = re.search(r'<([^<@\s]+)@([^\s]+)>', value)

        if m:
            username = m.group(1)
            domain = m.group(2)
            email = f'{username}@{domain}'

            if username.lower() in SMTPHeadersAnalysis.Dodgy_User_Names:
                result += self.logger.colored(f'- Username "{username}" in your sender email ({email}) might be increasing your SPAM score!\n', 'red')

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testDecodeEncodedHeaders(self):
        result = ''
        tmp = ''
        found = False
        num0 = 0
        shown = set()

        for (num, header, value) in self.headers:
            v = SMTPHeadersAnalysis.flattenLine(value)
            m = re.search(r'\=\?[a-z0-9\-]+\?Q\?', v, re.I)
            if m:
                num0 += 1

                SMTPHeadersAnalysis.Handled_Spam_Headers.append(header)

                value_decoded = emailheader.decode_header(value)[0][0]
                if type(value_decoded) == bytes:
                    value_decoded = value_decoded.decode(errors='ignore')

                hhh = self.logger.colored(header, 'magenta')
                tmp += f'\t({num0:02}) Header: {hhh}\n'
                tmp += f'\t     Value:\n\n'
                tmp += value_decoded + '\n\n'

                try:
                    x = SMTPHeadersAnalysis.hexdump(base64.b64decode(value_decoded.encode()))
                    tmp += f'\t     Base64 decoded Hexdump:\n\n'
                    tmp += x
                    tmp += '\n\n\n'
                except:
                    pass

                shown.add(header)

        if len(tmp) > 0:
            result = '- Decoded headers:\n\n'
            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': '...',
            'analysis' : result,
            'description' : '',
        }

    def testMicrosoftAntiSpamMessageInfo(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam-Message-Info')
        if num == -1: return []

        value = emailheader.decode_header(value)[0][0]
        if type(value) == bytes:
            value = value.decode(errors='ignore')

        self.addSecurityAppliance('MS ForeFront Anti-Spam')
        result = '- Base64 encoded & encrypted Antispam Message Info:\n\n'
        result += value

        tmp = ''

        if self.decode_all:
            tmp += f'\n\n\t- Base64 decoded Hexdump:\n\n'
            tmp += SMTPHeadersAnalysis.hexdump(base64.b64decode(value))
            tmp += '\n\n\n'
        else:
            tmp += '\n\n\t- Use --decode-all to print its hexdump.'

        result += tmp

        return {
            'header' : header,
            'value': '...',
            'analysis' : result,
            'description' : '',
        }

    def testAntispamMailboxDelivery(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam-Mailbox-Delivery')
        if num == -1: return []

        parsed = {}
        self.addSecurityAppliance('MS ForeFront Anti-Spam') 
        result = '- This header denotes where to move received message. Informs about applied Mail Rules, target directory in user\'s Inbox.\n\n'

        for entry in value.split(';'):
            if len(entry.strip()) == 0: continue
            k, v = entry.split(':')
            if k not in parsed.keys():
                parsed[k.lower()] = v

        if 'ucf' in parsed.keys() and 'dest' in parsed.keys() and parsed['ucf'] == '1' and parsed['dest'] == 'J':
            result += self.logger.colored(f'- WARNING: User created a custom mail rule that moved this message to JUNK folder!\n', "red")

        for k, v in parsed.items():
            elem = None

            if k.upper() in SMTPHeadersAnalysis.Forefront_Antispam_Delivery.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Delivery[k.upper()]

            elif k in SMTPHeadersAnalysis.Forefront_Antispam_Delivery.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Delivery[k]

            if elem:
                vals = v.split(',')
                found = False
                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- {k0}: ' + elem[0] + '\n'

                if type(elem[1]) == dict:
                    for va in vals:
                        if va in elem[1].keys():
                            found = True
                            tmp += f'\t- {va}: {elem[1][va]}\n'

                    if not found and len(v.strip()) > 0:
                        tmp += f'\t- Unknown value: "{v}" in parameter {k0}\n'
                        found = True
                
                elif len(v) > 0:
                    found = True
                    tmp += f'\t- {v}\n'

                if found:
                    result += tmp + '\n'

        for k in ['SFS', 'RULEID', 'ENG']:
            if k.lower() in parsed.keys():
                res = ''
                rules = [x.replace('(', '') for x in parsed[k.lower()].split(')')]

                if len(rules) == 1 and len(rules[0].strip()) == 0:
                    rules = []

                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- Message matched {self.logger.colored(len(rules), "yellow")} Anti-Spam Delivery rules ({k0}):\n'

                rules.sort()
                usedRE = False

                for r in rules:
                    if len(r) == 0: continue

                    r2 = f'({r})'
                    if r in SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered.keys():
                        e = SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered[r]
                        tmp += f'\t- {r2: <15} - {e}\n'
                        usedRE = True
                    else:
                        tmp += f'\t- {r2}\n'

                result += tmp + '\n'

        if usedRE:
            result += '\tNOTICE:\n'
            result += '\t(Anti-Spam rule explanation can only be considered as a clue, hint rather than a definitive explanation.)\n'
            result += '\t(Rules meaning was established merely in a trial-and-error process by observing SMTP header differences.)\n\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXDKIM(self):
        (num, header, value) = self.getHeader('X-DKIM')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        self.securityAppliances.add(value)
        result = f'- X-DKIM header was present and contained value: {vvv}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : 'This header typically indicates DKIM verification filter version.',
        }

    def testDKIMFilter(self):
        (num, header, value) = self.getHeader('DKIM-Filter')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        self.securityAppliances.add(value)
        result = f'- DKIM-Filter header was present and contained value: {vvv}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : 'This header typically indicates DKIM verification filter version.',
        }

    def testBypassFocusedInbox(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-Organization-BypassFocusedInbox')
        if num == -1: return []

        value = value.strip()

        result = f'- This message was marked with Bypass Focused Inbox specification:\n'
        
        if value.lower() == 'true' or value.lower() == 'yes':
            result += f'\t- The message will get to Inbox folder instead of Focused Inbox folder.\n'
        else:
            result += f'\t- The message might get into Focused Inbox folder.\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testO365EnhancedFilteringExternalOriginalInternetSender(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-ExternalOriginalInternetSender')
        if num == -1: return []

        description = '''
A custom mail flow rule was configured that supports Enhanced Filtering on Connector, as required by MS Defender for Office365.
This rule allows Exchange Online Protection determine the real source IP address and then do spam/spf etc. on the true sender IP and not the hop before Exchange Online Protection. 

Src:
https://c7solutions.com/2020/09/mail-flow-to-the-correct-exchange-online-connector
'''
        value = SMTPHeadersAnalysis.flattenLine(value).strip()

        result = f'- Office365 Enhanced Filtering for Connector was enabled facilitating Exchange Online Protection / MS Defender for Office365 protection.\n'
        result += f'- This header points at the original external Internet sender to be scanned with Enhanced Filtering:\n\n'

        parsed = {}
        for m in re.finditer(r'(\w+)=([^;]+)', value, re.I):
            parsed[m.group(1).lower()] = m.group(2)

        for k, v in parsed.items():
            result += f'\t- {self.logger.colored(k, "magenta"): <15}:   {self.logger.colored(v, "yellow")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testO365EnhancedFilteringSkipListedInternetSender(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-SkipListedInternetSender')
        if num == -1: return []

        description = '''
A custom mail flow rule was configured that supports Enhanced Filtering on Connector, as required by MS Defender for Office365.
This rule allows Exchange Online Protection determine the real source IP address and then do spam/spf etc. on the true sender IP and not the hop before Exchange Online Protection. 

Src:
https://c7solutions.com/2020/09/mail-flow-to-the-correct-exchange-online-connector
'''
        value = SMTPHeadersAnalysis.flattenLine(value).strip()

        result = f'- Office365 Enhanced Filtering for Connector was enabled facilitating Exchange Online Protection / MS Defender for Office365 protection.\n'
        result += f'- This header lists MTA servers that should be skipped from Enhanced Filtering scanning:\n\n'

        parsed = {}
        for m in re.finditer(r'(\w+)=([^;]+)', value, re.I):
            parsed[m.group(1).lower()] = m.group(2)

        for k, v in parsed.items():
            result += f'\t- {self.logger.colored(k, "magenta"): <15}:   {self.logger.colored(v, "yellow")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testXMailer(self):
        (num, header, value) = self.getHeader('X-Mailer')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        self.securityAppliances.add(value)
        result = f'- {self.logger.colored("X-Mailer","yellow")} header was present and contained value:\n\t- {vvv}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : 'This header typically indicates sending client\'s name (similar to User-Agent).',
        }

    def testO365FirstContactSafetyTip(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-EnableFirstContactSafetyTip')
        if num == -1: return []

        description = f'''
The initial method to implement the first contact safety tip was through a mail flow (transport) rule which inserts the X-MS-Exchange-EnableFirstContactSafetyTip x-header into external messages. The presence of the header causes Microsoft Defender to generate a safety tip if the sender has never sent email to the recipient before.

MS documentation explains it as follows: "Specific safety tips will be displayed notifying recipients that they often don’t get email from the sender or in cases when the recipient gets an email for the first time from the sender"

{self.logger.colored("This Mail Flow Rule is a custom one, not used in default installations.", "yellow")}

Src:
https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide
https://office365itpros.com/2020/11/26/enable-first-contact-safety-tip/
'''

        vvv = self.logger.colored(value, 'magenta')
        self.addSecurityAppliance('Exchange Online Protection')
        result = f'- The target\'s Office365 was configured with a First Contact Safety Tip:\n\t- {vvv}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : description,
        }

    def testMTAHostnamesExposed(self):
        if len(self.mtaHostnamesExposed) == 0:
            self.logger.info('No MTA hostnames exposed or they were not collected by running testReceived yet.')
            return []

        headers = []
        values = []

        description = '''
Some webmails or mail clients (such as MS Outlook) are known to attach system's Hostname to their "Received" header thus exposing it to all the other MTAs.
This can lead to an internal information disclosure. This test shows potential hostname values extracted from Received headers as server-names, that couldn't been resolved back to their IPv4/IPv6.
'''
        result = f'- Some MTAs (Mail Transfer Agents) probably exposed their internal Hostnames:\n'

        for hostname, hdr in self.mtaHostnamesExposed.items():
            result += f'\t- {self.logger.colored(hdr[1], "magenta"): <10} #{hdr[0]: <2}: {self.logger.colored(hostname, "red"): <20}'

            if hdr[0] == 1:
                result += self.logger.colored(f' (this might be the sender\'s computer hostname!)', "yellow")

            result += '\n'
            
            headers.append(hdr[1])
            4
            pos = hdr[2].lower().find(hostname.lower())
            val = hdr[2]
            
            if pos != -1:
                val = hdr[2][:pos] + self.logger.colored(hostname, "red") + hdr[2][pos + len(hostname):]

            values.append(val)

        return {
            'header' : ', '.join(headers),
            'value': '\n\n\t'.join(values),
            'analysis' : result,
            'description' : description,
        }

    def testXSpam(self):
        (num, header, value) = self.getHeader('X-Spam')
        if num == -1: return []

        vvv = SMTPHeadersAnalysis.flattenLine(value).strip()
        col = 'yellow'
        msg = ''
        if vvv.lower() == 'no': 
            col = 'green'
            msg = 'Not a spam'
        if vvv.lower() == 'yes': 
            col = 'red'
            msg = 'This message was a Spam'
        if vvv.find(' ') == -1: 
            vvv = vvv.upper()

        vvv = self.logger.colored(vvv, col)
        m = ''
        if len(msg) > 0:
            m = f' ({msg})'

        result = f'- X-Spam was set with:\n\t- {vvv}{m}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXAppInfo(self):
        (num, header, value) = self.getHeader('X-AppInfo')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        self.securityAppliances.add(value)
        result = f'- X-AppInfo header was present and contained value: {vvv}\n'
        result +  '  This header typically indicates sending client\'s name (similar to User-Agent).'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testUserAgent(self):
        (num, header, value) = self.getHeader('User-Agent')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        result = f'- User-Agent header was present and contained value: {vvv}\n'
        result +  '  This header typically indicates sending client\'s name (similar to X-Mailer).'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXMimecastBulkSignature(self):
        (num, header, value) = self.getHeader('X-Mimecast-Bulk-Signature')
        if num == -1: return []

        if value.strip().lower() == 'yes':
            result = f'- Mimecast considers the message as Bulk: {self.logger.colored(value.upper(), "red")}\n'
        else:
            result = f'- Mimecast does not consider the message as Bulk: {self.logger.colored(value.upper(), "green")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXMimecastSpamSignature(self):
        (num, header, value) = self.getHeader('X-Mimecast-Spam-Signature')
        if num == -1: return []

        result = f'- Mimecast considers the message as spam due to:\n\t- {self.logger.colored(value, "yellow")}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testXMimecastSpamScore(self):
        (num, header, value) = self.getHeader('X-Mimecast-Spam-Score')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        self.addSecurityAppliance('Mimecast')
        result = f'- Mimecast attached following Spam score: {vvv}\n'

        try:
            score = int(value.strip())

            if score < 3: 
                result += '\t- ' + self.logger.colored('Not a spam', 'green')

            if score >= 3 and score < 5: 
                result += '\t- ' + self.logger.colored('Low confidence it is a spam', 'green')

            if score > 5 and score <= 7: 
                result += '\t- ' + self.logger.colored('Medium confidence that might be a spam', 'yellow')

            if score > 7: 
                result += '\t- ' + self.logger.colored('High confidence - this is a SPAM', 'red')

        except:
            pass

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testTLCOObClasifiers(self):
        (num, header, value) = self.getHeader('X-MS-Oob-TLC-OOBClassifiers')
        if num == -1: return []

        result = f'- {self.logger.colored("OOB", "magenta")} Classifiers and their results:\n'
        value = value.replace(' ', '')

        for a in value.split(';'):
            if(len(a)) == 0: continue
            k, v = a.split(':')
            k0 = self.logger.colored(k, 'magenta')

            if k in SMTPHeadersAnalysis.TLCOOBClassifiers.keys():
                elem = SMTPHeadersAnalysis.TLCOOBClassifiers[k]

                if len(elem[0]) > 0:
                    result += f'\t- {k0}:{v} - ' + elem[0] + '\n'
                else:
                    result += f'\t- {k0}:{v}\n'

                if v in elem[1].keys():
                    result += f'\t\t- ' + elem[1][v] + '\n'
            else:
                result += f'\t- {k0}:{v}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testTransportEndToEndLatency(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-Transport-EndToEndLatency')
        if num == -1: return []

        result = f'- How much time did it take to deliver message from End-to-End: ' + self.logger.colored(value, 'cyan')

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testReceivedSPF(self):
        (num, header, value) = self.getHeader('Received-SPF')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value)
        result = ''
        words = [x.strip() for x in value.lower().split(' ') if len(x.strip()) > 0]
        
        if words[0] != 'pass':
            result += self.logger.colored(f'- Received-SPF test failed', 'red') + f'\n\t- Should be "{self.logger.colored("pass", "green")}", but was: "' + str(words[0]) + '"\n'

        result += '- Decomposition:\n'

        for part in value.split(';'):
            part = part.strip()

            if '=' in part:
                s = part.split('=')
                k = s[0]
                v = s[1]

                if k.lower() == 'client-ip':
                    result += f'\t- {self.logger.colored("client-ip", "green") + " " * 17}: {self.logger.colored(v.strip(), "green")}'

                    if self.resolve:
                        resolved = SMTPHeadersAnalysis.resolveAddress(value)

                        if len(resolved) > 0:
                            result += f'\t(resolved: {self.logger.colored(resolved, "magenta")})'

                        geo = self.collectIpGeo(v)
                        result += '\n\t' + str(textwrap.indent(geo, '\t\t'))

                    result += '\n'
                else:
                    result += f'\t- {k.strip():26}: {self.logger.colored(v.strip(), "yellow")}\n'
            else:
                result += f'\t- {self.logger.colored(part, "yellow")}\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def testAuthenticationResults(self):
        return self._testAuthenticationResults('Authentication-Results')

    def testARCAuthenticationResults(self):
        return self._testAuthenticationResults('ARC-Authentication-Results')

    def testXTMAuthenticationResults(self):
        return self._testAuthenticationResults('X-TM-Authentication-Results')

    def _testAuthenticationResults(self, targetHeader):
        headersCounted = 0
        headersCountedAll = 0

        for (num, header, value) in self.headers:
            if header.lower() == targetHeader.lower():
                headersCountedAll += 1

        for (num, header, value) in self.headers:
            if header.lower() == targetHeader.lower():
                headersCounted += 1
                SMTPHeadersAnalysis.Handled_Spam_Headers.append(header.lower())
                out = self._testAuthenticationResultsWorker(num, header, value)
                if out != []:
                    analysis = out['analysis']
                    result = f'- There were {self.logger.colored(headersCountedAll, "magenta")} headers named {self.logger.colored(targetHeader, "magenta")}. The {headersCounted}. one is considered problematic:\n'
                    out['analysis'] = result + '\n' + analysis
                    return out

        return []

    def _testAuthenticationResultsWorker(self, num, header, value):
        value = SMTPHeadersAnalysis.flattenLine(value)
        tests = {}
        result = ''

        for l in re.findall(r'([a-z]+=[a-zA-Z0-9]+)', value, re.I):
            a, b = l.lower().split('=')
            tests[a] = b

        for k in ['spf', 'dkim', 'dmarc']:
            expected = ['pass', ]
            
            if k == 'dmarc':
                expected.append('bestguesspass')

            if k in tests.keys() and tests[k] not in expected:
                p =  self.logger.colored('pass', 'green')
                p2 = self.logger.colored(tests[k], 'red')

                result += self.logger.colored(f'- {k.upper()} test failed:', 'red') + f'\n\t- Should be "{p}", but was: "' + p2 + '"\n'

                if k.lower() == 'dkim' and tests[k] in SMTPHeadersAnalysis.auth_result.keys():
                    result += '\t- Meaning: ' + SMTPHeadersAnalysis.auth_result[tests[k]] + '\n\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result,
            'description' : '',
        }

    def collectIpGeo(self, addr):
        if addr in self.ipgeoCache.keys():
            return self.ipgeoCache[addr]

        tmp = ''
        try:
            self.logger.dbg(f'testExtractIP: Collecting IP Geo metadata...')

            r = requests.get(
                f'http://ip-api.com/json/{addr}',
                headers = {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'en-US',
                    'Cache-Control': 'max-age=0',
                    'Connection': 'keep-alive',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
                }
            )
            out = r.json()

            if out != None and len(out) > 0 and type(out) is dict:
                tmp += f'\t\t- IP Geo metadata:\n'
                for k, v in out.items():
                    k1 = k
                    k = f'{k:12}'
                    if k1.lower() in ('country', 'regionName', 'city', 'isp', 'org', 'as'):
                        k = self.logger.colored(k, "cyan")
                        v = self.logger.colored(v, "green")
                    else:
                        v = self.logger.colored(v, "yellow")

                    tmp += f'\t\t\t- {k}: {v}\n'

        except Exception as e:
            pass

        self.ipgeoCache[addr] = tmp
        return tmp
        
    def testExtractIP(self):
        addresses = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', self.text)
        result = ''
        tmp = ''
        resolved = set()

        if len(addresses) == 0: return []

        self.logger.dbg('Running testExtractIP...')

        for addr in addresses:
            if addr in resolved: 
                continue

            try:
                resolved.add(addr)

                if self.resolve:
                    self.logger.dbg(f'testExtractIP: Resolving {addr}...')
                    out = SMTPHeadersAnalysis.resolveAddress(addr)

                    rawAddr = addr
                    addr = self.logger.colored(addr, 'magenta')
                    tmp += f'\n\t- Found IP address: {addr}\n'

                    if out != None and len(out) > 0 and out != addr:
                        tmp += f'\t\t- that resolves to: {out}\n'

                    tmp += str(textwrap.indent(self.collectIpGeo(rawAddr), '\t'))
                else:
                    addr = self.logger.colored(addr, 'magenta')
                    tmp += f'\t- Found IP address: {addr}\n'
            
            except Exception as e:
                tmp += f'\t- Found IP address: ({addr}) that wasn\'t resolved\n'

        if len(tmp) > 0:
            if self.resolve:
                result = '\n\t- Extracted IP addresses from headers and attempted to resolve them:\n\n'
            else:
                result = '\n\t- Extracted IP addresses from headers:\n\n'

            result += tmp.rstrip()

        if len(resolved) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : '\t' + result,
            'description' : '',
        }

    def testResolveIntoIP(self):
        #domains = set(re.findall(r'([a-z0-9_\-\.]+\.[a-zA-Z]{2,})', self.text, re.I))
        domains = set(re.findall(r'((?:[\w.-]+\.)+[\w]{2,})', self.text, re.I))
        resolved = set()
        result = ''
        tmp = ''

        skip = (
            'smtp.mailfrom',
            'header.from',
        )

        if len(domains) == 0: return []

        self.logger.dbg('Running testResolveIntoIP...')

        for d in domains:
            if d in resolved: continue
            if d in skip: continue

            if f'{d}@' in self.text: continue

            try:
                resolved.add(d)
                d2 = self.colorizeKeywords(d)

                if self.resolve:
                    self.logger.dbg(f'testResolveIntoIP: Resolving {d}...')
                    out = SMTPHeadersAnalysis.gethostbyname(d)

                    tmp += f'\n\t- Found Domain:   {self.logger.colored(d2, "yellow")}\n'

                    if len(out) > 0:
                        tmp += f'\t\t- that resolves to: {self.logger.colored(out, "cyan")}\n'
                        tmp += self.collectIpGeo(out)

                else:
                    tmp += f'\t- Found Domain:   {self.logger.colored(d2, "yellow")}\n'

            
            except Exception as e:
                tmp += f'\t- Found Domain:   ({self.logger.colored(d, "magenta")}) that wasn\'t resolved\n'

        if len(tmp) > 0:
            if self.resolve:
                result = '\n\t- Extracted domains from headers and attempted resolve them:\n\n'
            else:
                result = '\n\t- Extracted domains from headers:\n\n'

            result += tmp

        if len(resolved) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : '\t' + result,
            'description' : '',
        }

    def testBadKeywords(self):
        result = ''
        for num, header, value in self.headers:
            for w in SMTPHeadersAnalysis.bad_keywords:
                if w.lower() in value.lower():
                    SMTPHeadersAnalysis.Handled_Spam_Headers.append(header)
                    result += self.logger.colored(f'- Header\'s ({header}) value contained bad keyword: "{w}"\n', 'red')
                    result += f'  Value: {value}\n\n'

                elif w.lower() in header.lower():
                    SMTPHeadersAnalysis.Handled_Spam_Headers.append(header)
                    result += self.logger.colored(f'- Header\'s ({header}) name contained bad keyword: "{w}"\n\n', 'red')

        if len(result) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result,
            'description' : '',
        }

def opts(argv):
    global options
    global logger

    o = argparse.ArgumentParser(
        usage = 'decode-spam-headers.py [options] <file | --list tests>'
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('infile', help = 'Input file to be analysed or --list tests to show available tests.')

    opt = o.add_argument_group('Options')
    opt.add_argument('-o', '--outfile', default='', type=str, help = 'Output file with report')
    opt.add_argument('-f', '--format', choices=['json', 'text', 'html'], default='text', help='Analysis report format. JSON, text. Default: text')
    opt.add_argument('-N', '--nocolor', default=False, action='store_true', help='Dont use colors in text output.')
    opt.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose mode.')
    opt.add_argument('-d', '--debug', default=False, action='store_true', help='Debug mode.')

    tst = o.add_argument_group('Tests')
    opt.add_argument('-l', '--list', default=False, action='store_true', help='List available tests and quit. Use it like so: --list tests')
    tst.add_argument('-i', '--include-tests', default='', metavar='tests', help='Comma-separated list of test IDs to run. Ex. --include-tests 1,3,7')
    tst.add_argument('-e', '--exclude-tests', default='', metavar='tests', help='Comma-separated list of test IDs to skip. Ex. --exclude-tests 1,3,7')
    tst.add_argument('-r', '--resolve', default=False, action='store_true', help='Resolve IPv4 addresses / Domain names & collect IP Geo metadata.')
    tst.add_argument('-R', '--dont-resolve', default=False, action='store_true', help='Do not resolve anything.')
    tst.add_argument('-a', '--decode-all', default=False, action='store_true', help='Decode all =?us-ascii?Q? mail encoded messages and print their contents.')
    tst.add_argument('-U', '--no-unusual', default=False, action='store_true', help='Do not print SMTP headers this script considers as unusual.')

    args = o.parse_args()

    if len(args.outfile) > 0 and (args.format == 'json' or args.format == 'text'):
        args.nocolor = True

    options.update(vars(args))
    logger = Logger(options)

    return args

def printOutput(out):
    output = ''

    testStart = '-----------------------------------------'
    testEnd = ''

    if options['format'] == 'html':
        testStart = '>>>>>>>>>>>>>>>>>>>>>>'
        testEnd   = '<<<<<<<<<<<<<<<<<<<<<<'

    if options['format'] == 'text' or options['format'] == 'html':
        width = 100
        num = 0

        for k, v in out.items():
            num += 1
            analysis = v['analysis']
            value = v['value']

            analysis = analysis.strip()
            if analysis.startswith('\n'): analysis[1:]

            value = str(textwrap.fill(
                v['value'], 
                width=width - 1, 
                subsequent_indent=' ' * 4, 
                initial_indent='', 
                replace_whitespace=False,
            )).strip()

            description = ''

            if len(v['description']) > 1:
                desc = v['description']
                desc = '\n'.join(textwrap.wrap(
                    desc, 
                    width=width - 1, 
                    subsequent_indent=' ' * 4, 
                    initial_indent='', 
                    replace_whitespace=True,
                )).strip()

                description = f'''
{logger.colored("DESCRIPTION", "blue")}: 
    {desc}
'''

            if len(v['header']) > 1 or len(value) > 1:
                output += f'''
{testStart}
({num}) Test: {logger.colored(k, "cyan")}

{logger.colored("HEADER", "blue")}: 
    {v['header']}
{description}
{logger.colored("VALUE", "blue")}: 
    {value}

{logger.colored("ANALYSIS", "blue")}:

{analysis}
{testEnd}
'''
            else:
                output += f'''
{testStart}
({num}) Test: {logger.colored(k, "cyan")}

{logger.colored("ANALYSIS", "blue")}:

{analysis}
{testEnd}
'''

    elif options['format'] == 'json':
        output = json.dumps(out)

    return output

def formatToHtml(body, headers):
    testStart = '>>>>>>>>>>>>>>>>>>>>>>'
    testEnd   = '<<<<<<<<<<<<<<<<<<<<<<'

    body = body.replace(testStart, '<div><hr/>')
    body = body.replace(testEnd,   '</div>')

    body = body.replace('\n', '<br/>\n').replace('\t', '\t' + '&nbsp;' * 4).replace(' ', '&nbsp;')
    headers = headers.replace('\n', '<br/>\n').replace('\t', '\t' + '&nbsp;' * 4).replace(' ', '&nbsp;')
    body2 = body

    for m in re.finditer(r'(<[^>]+>)', body, re.I):
        a = m.group(1)
        b = a.replace('&nbsp;', ' ')
        body2 = body2.replace(a, b)

    body = body2

    outputHtml = f'''
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Decode Spam Headers</title>
  </head>
  <style>
  body {{
    background-color:{Logger.html_colors_map['background']};
    color: {Logger.html_colors_map['white']};
    font-family: Consolas, monaco, monospace;
    font-size: 14px;
    font-style: normal;
    font-variant: normal;
    font-weight: 400;
    line-height: 20px;
  }}

  .text-white {{
    color: {Logger.html_colors_map['white']};
  }}

  .text-grey {{
    color: {Logger.html_colors_map['grey']};
  }}

  .text-red {{
    color: {Logger.html_colors_map['red']};
  }}

  .text-green {{
    color: {Logger.html_colors_map['green']};
  }}

  .text-yellow {{
    color: {Logger.html_colors_map['yellow']};
  }}

  .text-blue {{
    color: {Logger.html_colors_map['blue']};
  }}

  .text-magenta {{
    color: {Logger.html_colors_map['magenta']};
  }}  

  .text-cyan {{
    color: {Logger.html_colors_map['cyan']};
  }}

  h1 {{
 font-family: Consolas, monaco, monospace;
 font-size: 24px;
 font-style: normal;
 font-variant: normal;
 font-weight: 700;
 line-height: 26.4px;
 }}

 h3 {{
 font-family: Consolas, monaco, monospace;
 font-size: 14px;
 font-style: normal;
 font-variant: normal;
 font-weight: 700;
 line-height: 15.4px;
 }}

 p {{
 font-family: Consolas, monaco, monospace;
 font-size: 14px;
 font-style: normal;
 font-variant: normal;
 font-weight: 400;
 line-height: 20px;
 }}

 blockquote {{
 font-family: Consolas, monaco, monospace;
 font-size: 14px;
 font-style: normal;
 font-variant: normal;
 font-weight: 400;
 line-height: 30px;
 }}

 pre {{
 font-family: Consolas, monaco, monospace;
 font-size: 13px;
 font-style: normal;
 font-variant: normal;
 font-weight: 400;
 line-height: 18.5714px;
 }}

 summary::-webkit-details-marker {{
  color: #00ACF3;
  font-size: 125%;
  margin-right: 2px;
}}

summary:focus {{
    outline-style: none;
}}

article > details > summary {{
    font-size: 18px;
    margin-top: 16px;
}}

details > p {{
    margin-left: 14px;
}}

blockquote code {{
    background-color: rgba(0, 0, 0, .07);
    display: block;
    font-family: Consolas, monaco, monospace;
    font-size: 13px;
    font-style: normal;
    font-variant: normal;
    font-weight: 400;
    line-height: 18.5714px;    
}}

a {{
   color: {Logger.html_colors_map['green']};
   text-decoration: none;
}}

  </style>
  <body>
    <div>
        <br/>
        <h2>
        SMTP Headers analysis by <a href="https://github.com/mgeeky/decode-spam-headers">decode-spam-headers.py</a>
        </h2>
        <i style=".text-grey">(brought to you by <a style="size:8px" href="https://twitter.com/mariuszbit">@mariuszbit</a>)</i>
        <br/>
        <br/>
        <br/>
        <article>
          <details>
            <summary>Original SMTP Headers</summary>
            <blockquote>
            <code>
{headers}
            </code>
            </blockquote>
          </details>
        </article>
        <br/>
    </div>
    {body}
  </body>
</html>
'''     
    return outputHtml

def colorizeOutput(out, headers):
    if options['format'] == 'html':
        out = Logger.htmlColors(out)
        return formatToHtml(out, headers)

    if options['format'] == 'text':
        out = Logger.ansiColors(out)

    if options['format'] == 'json' or len(options['outfile']) > 0:
        out = Logger.noColors(out)

    return out

def main(argv):
    args = opts(argv)
    if not args:
        return False

    if args.list:
        print('[.] Available tests:\n')

        print('\tTEST_ID - TEST_NAME')
        print('\t--------------------------------------')

        an = SMTPHeadersAnalysis(logger)

        (a, b, c) = an.getAllTests()
        d = a+b+c
        e = [x for x in sorted(d, key=lambda item: int(item[0]))]

        for test in e:
            (testId, testName, testFunc) = test

            if test in b:
                testName += ' (use -a to show its results)'
            print(f'\t{testId: >7} - {testName}')

        print('\n')
        return True

    logger.info('Analysing: ' + args.infile)

    an0 = SMTPHeadersAnalysis(logger)
    (a, b, c) = an0.getAllTests()
    maxTest = 0
    for i in a+b+c:
        test = int(i[0])

        if test > maxTest:
            maxTest = test

    text = ''
    with open(args.infile) as f:
        text = f.read()

    try:
        include_tests = set()
        exclude_tests = set()

        if len(args.include_tests) > 0: include_tests = set([int(x) for x in args.include_tests.replace(' ', '').split(',')])
        if len(args.exclude_tests) > 0: exclude_tests = set([int(x) for x in args.exclude_tests.replace(' ', '').split(',')])

        if len(include_tests) > 0 and len(exclude_tests) > 0:
            logger.fatal('--include-tests and --exclude-tests options are mutually exclusive!')
    except:
        raise
        logger.fatal('Tests to be included/excluded need to be numbers! Ex. --include-tests 1,5,7')

    _testsToRun = set()

    for i in range(maxTest + 5):
        if len(include_tests) > 0:
            if i not in include_tests:
                continue

        elif len(exclude_tests) > 0:
            if i in exclude_tests:
                continue
        
        _testsToRun.add(i)

    testsToRun = sorted(_testsToRun)

    an = SMTPHeadersAnalysis(logger, args.resolve, args.decode_all, testsToRun, not args.no_unusual)
    out = an.parse(text)

    printed = printOutput(out)
    output = colorizeOutput(printed, text)

    if len(args.outfile) > 0:
        with open(args.outfile, 'w') as f:
            f.write(output)
    else:
        print(output)

        if not options['nocolor']:
            print('''
------------------------------------------

Experiencing a bad-looking output with unprintable characters? 
Use -N flag to disable console colors, or switch your console for better UI experience.
''')

if __name__ == '__main__':
    main(sys.argv)


@atexit.register
def goodbye():
    colorama.deinit()

