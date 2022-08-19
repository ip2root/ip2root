import xml.dom.minidom

def parse_nmap_xml(target:str) -> str:

    doc = xml.dom.minidom.parseString(target)

    ports = doc.getElementsByTagName("port")
    for portid in ports:
        print(portid.getAttribute("portid"))