import subprocess

def nmap_scan(ip: str) -> str:
    command = 'nmap -A {}'.format(ip)
    print('[+] Running nmap scan on {}'.format(ip))
    command_result = subprocess.run(command, shell=True, capture_output=True)
    print('[+] nmap scan result :\n{}'.format(command_result.stdout.decode('utf-8')))