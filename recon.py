from libnmap.process import NmapProcess
import masscan
import json
from utils import *

def nmap_scan(targets_open_ports: dict) -> list:
    """
    Run nmap scan and return a list of open ports
    """
    res_nmap_scans = []
    for target_ip, ports in targets_open_ports.items():
        formated_ports = list(map(str,ports))
        print(formated_ports)
        nmap_proc = NmapProcess(target_ip, '-A -p {}'.format(','.join(formated_ports)))
        print('[+] Running nmap scan on {}'.format(target_ip))
        nmap_proc.run()
        open_ports = parse_nmap_xml(nmap_proc.stdout)

        res_scan = []
        for port in open_ports:
            print('[+] Detected port {} {} : {} {} {} {}'.format(port['port_num'], port['state'], port['protocol'], port['service_type'], port['product_name'], port['product_version'], safe_get(port, 'extrainfo')))
            res_port = {
                'port': port['port_num'],
                'proto': port['protocol'],
                'service': port['service_type'],
                'product': port['product_name'],
                'version': port['product_version'],
                'extrainfo': safe_get(port, 'extrainfo'),
                'http_title': safe_get(port, 'http_title')
            }
            to_del = []
            for key in res_port:
                if res_port[key] == '':
                    to_del.append(key)
            for k in to_del:
                del res_port[k]
            res_scan.append(res_port)
        res_nmap_scans.append(res_scan)
    return res_nmap_scans

def masscan_scan(targets: str) -> list:
    """
    Run masscan scan and return a list of open ports
    """
    print('[+] Running masscan on {}'.format(targets))
    mas = masscan.PortScanner()
    print('targets :'+targets)
    mas.scan(targets, ports='0-65535', arguments='--max-rate 1000000')
    print(mas.scan_result)
    targets_open_ports = {}
    masscan_results = json.loads(mas.scan_result)['scan']
    for ip, ports in masscan_results.items():
        open_ports = []
        for port in ports:
            open_ports.append(port['port'])
        targets_open_ports.update({ip:open_ports})
    return targets_open_ports