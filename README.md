# ip2root

This tool aims to provide a root shell from a simple IP.

## DISCLAIMER

The tool has been created for pentesters and redteamers and should only be used against targets you have rights on.
We are not responsible of the actions done by your usage of the tool.

## Contribution

Any contribution would be appraciated. You can create a pull request to propose an imporvement or new exploits (initial access or privesc) :).

##  How to

### 1. Clone repo

```shell
git clone git@github.com:0xblank/ip2root.git
```

### 2. Create a venv

```shell
python3 -m venv venv_ip2root
source venv_ip2root/bin/activate
```

### 3. Install required dependencies

```shell
pip3 install -r requirements.txt
```

### 4. Run ip2root

```shell
python3 main.py -t <target_ip>
```
