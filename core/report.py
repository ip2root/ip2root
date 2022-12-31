from core.utils import *

def write_report(compromission_recap_file_name: str, plugin_config: list, target_ip: str, target_port: int) -> bool:
    with open(compromission_recap_file_name, 'w') as report:
        report.write('# IP2ROOT report\n\n')
        report.write('## IP address and Port\n`{}:{}`\n'.format(target_ip, target_port))
        report.write('## Vulnerability used for initial access\n')
        report.write('#### Service : `{}`\n'.format(safe_get(plugin_config, 'service')))
        report.write('#### Version : `{}`\n'.format(safe_get(plugin_config, 'versions')))
        if safe_get(plugin_config, 'CVE'):
            report.write('#### CVE : `{}`\n'.format(safe_get(plugin_config, 'CVE')))
        if safe_get(plugin_config, 'CVSSv3'):
            report.write('#### CVSSv3 : `{}`\n'.format(safe_get(plugin_config, 'CVSSv3')))
    return True