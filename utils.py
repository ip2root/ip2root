import xml.dom.minidom

def parse_nmap_xml(target:str) -> str:

    doc = xml.dom.minidom.parseString(target)
    ports_xml = doc.getElementsByTagName('port')
    open_ports = []
    for port_id in ports_xml:
        open_ports.append(port_id.getAttribute('portid'))
    return(open_ports)