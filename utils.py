import xml.dom.minidom
import ipaddress 

def parse_nmap_xml(target:str) -> str:

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
        open_ports.append(port)
    return(open_ports)

def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print("[-] Error: IP address {} is not valid".format(address))
        exit(1)