from libnmap.process import NmapProcess
from utils import *

def nmap_scan(ip: str, port: int | None) -> list:
    """
    Run nmap scan and return a list of open ports
    """
    if port:
        nmap_proc = NmapProcess(ip, '-A -p {}'.format(port))
    else:
        nmap_proc = NmapProcess(ip, '-A')
    print('[+] Running nmap scan on {}'.format(ip))
    nmap_proc.run()
    open_ports = parse_nmap_xml(nmap_proc.stdout)

    res_recon = []
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
        res_recon.append(res_port)
    return res_recon