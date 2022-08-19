import subprocess
from libnmap.process import NmapProcess
import utils

def nmap_scan(ip: str) -> str:
    nmap_proc = NmapProcess(ip, '-A')
    nmap_proc.run()
    print('[+] Running nmap scan on {}'.format(ip))
    print('[+] nmap scan result :\n{}\n{}'.format(nmap_proc.stdout, nmap_proc.stderr))
    utils.parse_nmap_xml(nmap_proc.stdout)