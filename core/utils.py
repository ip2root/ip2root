import ipaddress
import xml.dom.minidom
from typing import Any

def parse_nmap_xml(target: str) -> str:
    """
    Parse xml results from a nmap scan
    """
    doc = xml.dom.minidom.parseString(target)
    ports_xml = doc.getElementsByTagName('port')
    open_ports = []
    for i, port_xml in enumerate(ports_xml):
        port = {}
        port['port_num'] = port_xml.getAttribute('portid')
        port['protocol'] = port_xml.getAttribute('protocol')
        state = doc.getElementsByTagName('state')[i]
        port['state'] = state.getAttribute('state')
        service = doc.getElementsByTagName('service')[i]
        port['service_type'] = service.getAttribute('name')
        port['product_name'] = service.getAttribute('product')
        port['product_version'] = service.getAttribute('version')
        port['extrainfo'] = service.getAttribute('extrainfo')
        scripts = doc.getElementsByTagName('script')
        for res_script in scripts:
            if res_script.getAttribute('id') == 'http-title':
                port['http_title'] = res_script.getAttribute('output')
        open_ports.append(port)
    return(open_ports)

def validate_ip_address(address: str) -> None:
    """
    Check if the string is a correct IP address
    """
    try:
        ipaddress.ip_address(address)
    except ValueError:
        print("[-] Error: IP address {} is not valid".format(address))
        exit(1)

def prompt(message: str) -> bool:
    """
    Handle a yes/no prompt
    """
    answer = ""
    while(answer != "Y" and answer != "N"):
        answer = input(message + " (Y/N): ")
        answer = answer.upper()
    return answer == "Y"

def safe_get(dict: dict, key: Any) -> Any | None:
    if key in dict.keys():
        return dict[key]
    else:
        return None
