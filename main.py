import argparse
import subprocess

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target_ip', type=str, help='ip to target')
    args = parser.parse_args()

    command = 'nmap -A {}'.format(args.target_ip)
    print('[+] Running nmap scan on {}'.format(args.target_ip))
    command_result = subprocess.run(command, shell=True, capture_output=True)
    print('[+] nmap scan result :\n{}'.format(command_result.stdout.decode('utf-8')))