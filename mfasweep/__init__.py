#!/usr/bin/env python3

import requests
import getpass
import argparse
import sys
import re
import json
import imaplib
import poplib
import smtplib
from colorama import init, Fore
from base64 import b64encode
from xml.etree import ElementTree


class MFASweep():


    def __init__(self, args: argparse.Namespace):
        self.username = f'{args.user}@{args.domain}'
        self.domain = args.domain
        self.password = getpass.getpass('Enter password: ')
        
        # Initialize colorama
        init()
        print('\033[1A\r\033[1m[==  MFASweep.py  ==]\033[0m')
        print(Fore.RESET + '\033[1A\r')


        # Set RE compilations
        self.ctxRE = re.compile(r'ctx=(.*?)"')
        self.flowTokenRE = re.compile(r'sFT":"(.*?)"')
        self.canaryRE = re.compile(r'apiCanary":"(.*?)"')

        self.adfs = False
        self.cookies = None

        self.Recon()
        self.O365WebPortalAuth(mobile=False)
        self.O365WebPortalAuth(mobile=True)
        self.GraphAPIAuth()
        self.AzureManagementAPIAuth()
        self.O365ActiveSyncAuth()
        # These are not yet done
        #self.O365Imap()
        #self.O365POP3()
        #self.O365SMTP()
        self.ADFSAuth()

    def log(self, logtype, msg):
        if logtype == 'error':
            col = Fore.RED
            msg = f'[!] {msg}'
        elif logtype == 'warn':
            col = Fore.YELLOW
            msg = f'[+] {msg}'
        elif logtype == 'info':
            col = Fore.GREEN
            msg = f'[-] {msg}'

        print(col + msg)
        print(Fore.RESET + '\033[1A\r')


    def PrintHeader(self, authmethod: str):
        print(f'~~: \033[1m{authmethod}\033[0m')


    def Recon(self):
        self.PrintHeader('Reconnaissance')
        uri = f'https://login.microsoftonline.com/getuserrealm.srf?login={self.username}&xml=1'
        response = requests.get(uri)
        xmlTree = ElementTree.fromstring(response.text)

        try:
            ADFSUrl = xmlTree.find('AuthURL').text
            self.log('warn', f'{self.domain} uses ADFS on URL: {ADFSUrl.split("?")[0]}')
            self.adfs = True
        except AttributeError:
            self.log('error', f'{self.domain} does not use ADFS')

        # TODO: Look at NameSpaceType
        

    def EWSAuth(self):
        # https://outlook.office365.com/EWS/Exchange.asmx
        pass


    def O365WebPortalAuth(self, mobile: bool):
        if mobile:
            self.PrintHeader(f'Office 365 Portal Auth via Mobile')
        else:
            self.PrintHeader(f'Office 365 Portal Auth via Browser')
        uri = 'https://outlook.office365.com'

        O365Session = requests.session()
        if mobile:
            O365Session.headers.update({'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Mobile Safari/537.36'})
        else:
            O365Session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0'})
        session = O365Session.get(uri)

        ctx = re.findall(self.ctxRE, session.text)[0]
        flowToken = re.findall(self.flowTokenRE, session.text)[0]
        O365Session.headers.update({'canary': re.findall(self.canaryRE, session.text)[0]})
        O365Session.headers.update({'Content-type': 'application/json; charset=utf-8'})
        O365Session.headers.update({'Origin': 'https://login.microsoft.com'})

        form = {
            'username': self.username,
            'isOtherIdpSupported': "false",
            'checkPhones': "false",
            'isRemoteNGCSupported': "true",
            'isCookieBannerShown': "false",
            'isFidoSupported': "false",
            'originalRequest': ctx,
            'country': "DK",
            'forceotclogin': "false",
            'isExternalFederationDisallowed': "false",
            'isRemoteConnectSupported': "false",
            'federationFlags': "0",
            'isSignup': "false",
            'flowToken': flowToken,
            'isAccessPassSupported': "true"
        }

        userrequest = O365Session.post('https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US', json=form)
        
        auth = {
            'login': self.username,
            'loginfmt': self.username,
            'type': '11',
            'LoginOptions': '3',
            'lrt': '',
            'lrtPartition': '',
            'hisRegion': '',
            'hisScaleUnit': '',
            'passwd': self.password,
            'ps': '2',
            'psRNGCDefaultType': '',
            'psRNGCEntropy': '',
            'psRNGCSLK': '',
            'canary': '',
            'ctx': ctx,
            'hpgrequestid': '',
            'flowToken': flowToken,
            'NewUser':'1',
            'FoundMSAs': '',
            'fspost': '0',
            'i21': '0',
            'CookieDisclosure': '0',
            'IsFidoSupported': '1',
            'isSignupPost': '0',
            'i2': '1',
            'i17': '',
            'i18': '',
            'i19': '198733',
        }

        authrequest = O365Session.post('https://login.microsoftonline.com/common/login', json=auth)
        
        if O365Session.cookies.get('estsauth') or O365Session.cookies.get('ESTSAUTH'):
            self.log('info', 'Login via O365 Web portal successful')
            mfaNotRequired = re.findall('Stay signed in', authrequest.text)[0]
            if mfaNotRequired:
                self.log('error', 'MFA not required for O365 Web portal login')
                self.log('error', f'Use {O365Session.cookies.get_dict()} for browser login')
            else:
                self.log('info', 'Unsuccessful login to O365 Web portal. 2-step validation required.')
        else:
            self.log('info', 'Unsuccessful login to O365 Web portal')


    def GraphAPIAuth(self):
        self.PrintHeader('Graph API')
        uri = 'https://login.microsoft.com'

        body = {
            'resource': 'https://graph.windows.net',
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
            'client_info': '1',
            'grant_type': 'password',
            'username': self.username,
            'password': self.password,
            'scope': 'openid',
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(f'{uri}/common/oauth2/token', headers=headers, data=body)

        if response.status_code == 200:
            self.log('error', 'Valid login to GraphAPI')
        else:
            self.log('info', 'Unsuccessful login to GraphAPI')


    def AzureManagementAPIAuth(self):
        self.PrintHeader('Azure Management API')
        uri = 'https://login.microsoftonline.com'

        body = {
            'resource': 'https://management.core.windows.net',
            'client_id': '1950a258-227b-4e31-a9cf-717495945fc2',
            'grant_type': 'password',
            'username': self.username,
            'password': self.password,
            'scope': 'openid'
        }
        header = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(f'{uri}/common/oauth2/token', headers=header, data=body)

        if response.status_code == 200:
            self.log('error', 'Valid login to Azure Mangement API')
        else:
            self.log('info', 'Unsuccessful login to Azure Management API')


    def O365ActiveSyncAuth(self):
        self.PrintHeader('Office 365 ActiveSync')
        session = requests.Session()
        uri = 'https://outlook.office365.com/Microsoft-Server-ActiveSync'

        header = {
            'Authorization': f'Basic {b64encode(bytes(f"{self.username}:{self.password}", encoding="utf-8")).decode("utf-8")}'
        }

        response = session.get(uri, headers=header)

        if response.status_code == 505:
            self.log('error', 'Valid login to ActiveSync successful')
            self.log('error', 'Note: Windows 10 Mail app can connect this way')
        else:
            self.log('info', 'Unsuccessful login to ActiveSync')


    def O365Imap(self):
        self.PrintHeader('Office 365 IMAP')
        mail = imaplib.IMAP4_SSL(host='outlook.office365.com', port=993)
        capabilities = mail.capabilities

        caps = ''
        for capability in capabilities:
            caps += f'{capability} '
        self.log('warn', f'IMAP capabilities: {caps}')
        try:
            mail.login(self.username, self.password)
        except imaplib.IMAP4.error:
            self.log('info', 'Unsuccessfull login via IMAP. 2-step validation required.')

        # TODO: On success:
        #_, folders = mail.list()
        #for folder in folders:
        #    print(folder)

    
    def O365POP3(self):
        self.PrintHeader('Office 365 POP3')
        pop = poplib.POP3_SSL(host='outlook.office365.com', port=995)
        #pop.set_debuglevel(2)
        r = pop.user(self.username)
        if 'OK' in r.decode('utf-8'):
            try:
                pop.pass_(self.password)
                # TODO: finish
            except poplib.error_proto:
                self.log('info', 'Unsuccessfull login via POP3. 2-step validation required.')
            

    def O365SMTP(self):
        self.PrintHeader('Office 365 SMTP')
        smtp = smtplib.SMTP(host='smtp.office365.com', port=587)
        smtp.set_debuglevel(2)
        smtp.starttls()
        smtp.login(self.username, self.password)


    def ADFSAuth(self):
        pass


def main(args):
    parser = argparse.ArgumentParser(prog='MFASweep')

    parser.add_argument('user', type=str, help='Username to use during test')
    parser.add_argument('domain', type=str, help='Domain of user')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()

    mfasweep = MFASweep(args)
