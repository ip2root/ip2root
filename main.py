import argparse
import recon

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target')
    args = parser.parse_args()
    recon.nmap_scan(args.target_ip)