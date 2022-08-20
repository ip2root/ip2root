import subprocess
from libnmap.process import NmapProcess
import utils

def nmap_scan(ip: str) -> str:
    nmap_proc = NmapProcess(ip, '-A')
    print('[+] Running nmap scan on {}'.format(ip))
    nmap_proc.run()
    open_ports = utils.parse_nmap_xml(nmap_proc.stdout)
    for port in open_ports:
        print('[+] Detected port {} {} : {} {} {} {}'.format(port['port_num'], port['state'], port['protocol'], port['service_type'], port['product_name'], port['product_version']))