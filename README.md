# ip2root

This tool aims to provide a root shell from a simple IP.

## DISCLAIMER

The tool has been created for pentesters and redteamers and should only be used against targets you have rights on.
We are not responsible of the actions done by your usage of the tool.

## Contribution

Any contribution would be appraciated. You can create a pull request to propose an imporvement or new exploits (initial access or privesc) :).

##  How to use to tool

### 1. Clone repo

```shell
git clone git@github.com:0xblank/ip2root.git
```

### 2. Create a venv (optional)

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

# How to contribute

## Initial access plugin

Name your python file like this `serviceversionvuln.py` ex: `apache2_4_49RCE.py`, create a config file with the same name but ending with `.ini` and place them in the `plugins/initial_access` directory. The config file should follow the following format :

```ini
[DEFAULT]
plugin_name = <name of your plugin>
service = <name of the vulnerable service>
versions = <versions number>
```

The plugin_name should be the exact same as your python file (case sensitive), the service name should be the same as the name returned by nmap (case sensitive), the versions number should have the same format that the one returned by nmap, you can specify mutliple versions numbers.

## Privesc plugins

Privesc script must be written in bash for linux targets and in .bat or .ps1 for windows targets.