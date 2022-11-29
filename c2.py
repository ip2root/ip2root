import docker
import os
import subprocess
import requests
import json
from time import sleep

def c2() -> None | str:
    is_up = 0
    client = docker.from_env()
    if len(client.containers.list(all))-1 > 1:
        for i in (0,len(client.containers.list(all))-1):
            container = client.containers.get(client.containers.list(all)[i].__getattribute__('short_id'))
            if "empire" in container.attrs['Config']['Image']:
                print('[+] Detected an existing C2 container')
                is_up = 1
                client.containers.list(all)[i].start()
                sleep(25)
                token = c2_token()
                print('[+] C2 started successfully from existing docker (ID: {0}'.format(client.containers.list(all)[i].short_id))
                print('[+] Listening on port 8888 (CLIHTTP)')
                return client.containers.list(all)[i].short_id, token
        if is_up == 0:
            infos = deploy_c2()
            return infos
    else:
        infos = deploy_c2() 
        return infos

def starkiller():
    STARKILLER_PATH = '/tmp/starkiller'
    if not os.path.exists(STARKILLER_PATH):
        STARKILLER_URL = 'https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage'
        print('[+] Downloading starkiller in {} from {}'.format(STARKILLER_PATH, STARKILLER_URL))
        r_github = requests.get(STARKILLER_URL, allow_redirects=True)
        open(STARKILLER_PATH, 'wb').write(r_github.content)
    subprocess.Popen(["chmod", "+x", STARKILLER_PATH])
    subprocess.Popen([STARKILLER_PATH])

def deploy_c2():
    print('[+] Deploying C2 container')
    C2_LISTENER_PORT = 8888
    client = docker.from_env()
    container = client.containers.run(image='bcsecurity/empire:latest', ports={'1337/tcp':1337, '5000/tcp':5000, '{}/tcp'.format(C2_LISTENER_PORT):C2_LISTENER_PORT}, name='empire', tty=True, detach=True)
    container.wait() # Does not wait everytime
    token = c2_token()
    print('[+] C2 container created successfully (Docker ID : {0}'.format(container.short_id))
    print('[+] Listener created on port {} (CLIHTTP)'.format(C2_LISTENER_PORT))
    return container.short_id, token

def c2_token():
    url_c2 = 'https://localhost:1337/api/admin/login'
    headers = {"Content-Type": "application/json"}
    param = {"username":"empireadmin", "password":"password123"}
    r_c2 = requests.post(url_c2, headers=headers, json=param, verify=False)
    json_token = json.loads(r_c2.text)
    token = json_token['token']
    url_listener = 'https://localhost:1337/api/listeners/http?token={0}'.format(str(token))
    param_listener = {"Name":"CLIHTTP", "Port":"8888"}
    r_listener = requests.post(url_listener, headers=headers, json=param_listener, verify=False)
    return token

def get_stager(system):
    if system == 'linux':
        print(system)
    elif system == 'windows':
        print(system)
    else:
        return "[-] Error: OS not defined."
