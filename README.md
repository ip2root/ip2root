# IP2ROOT

This tool aims to provide a root shell from a simple IP.

WARNING : The tool is currently in an early state of release. You can track progress [here](https://github.com/orgs/ip2root/projects/1)

## DISCLAIMER

The tool has been created to help pentesters and redteamers and should only be used against targets you have rights on.
We are not responsible of the actions done by your usage of the tool.

##  How to use the tool

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
python3 main.py -t <target_ip> [-l <local-ip>] [-p <local-port>]
```

# How to contribute
Any contribution would be appraciated (improvement, new exploits, etc.).

## Initial access plugin

Name your python file like this `serviceversionvuln.py` ex: `apache2_4_49RCE.py`, create a config file with the same name but ending with `.ini` and place them in the `plugins/initial_access` directory. The config file should match the following format :

```ini
[DEFAULT]
plugin_name = <name of your plugin>
service = <name of the vulnerable service>
versions = <versions number>
```

The plugin_name should be the exact same as your python file (case sensitive).
The service name should be the same as the name returned by nmap (case sensitive).
The versions number should have the same format that the one returned by nmap. You can specify mutliple versions numbers.

## Privesc plugins

Privesc script must be written in bash for linux targets and in .bat or .ps1 for windows targets.

# Licence


The following tool is under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public licence.

You are free to:

* Share — copy and redistribute the material in any medium or format
* Adapt — remix, transform, and build upon the material 

Under the following terms:

* Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* NonCommercial — You may not use the material for commercial purposes.
* ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original. 

Please refer to the [licence](https://github.com/ip2root/ip2root/blob/master/COPYING.md).
