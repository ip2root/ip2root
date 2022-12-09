![](https://md.floppy.sh/uploads/ab5e7ff1-3d92-4aa5-8166-54c88929e94e.png)

![Python minimum version](https://img.shields.io/badge/Python-3.10%2B-brightgreen)

## Description

This tool aims to provide a root shell from a simple IP.

:warning: WARNING :warning: : This tool is currently in development. You can track progress [here](https://github.com/orgs/ip2root/projects/1)
Pull requests are welcome.

## Disclaimer

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
python3 main.py -t <target_ip> [-l <local-ip>] [-lp <local-port>] [-rp <remote-port>] [-o <output.md>]
```

### Troubleshooting

#### Masscan

If you have encounter the following error message
```shell=
[-] FAIL: permission denied
    [hint] need to sudo or run as root or something
[-] if:wlp1s0:init: failed
```
This means you need to add `CAP_NET_RAW` to masscan to be able to run it without being root. You can use the following command to do so : `sudo setcap CAP_NET_RAW+ep <masscan path>`

## How to contribute

Any contribution would be appreciated (improvement, new exploits, etc.).

### Initial access plugin

Name your python file like this `service_version_vuln.py` ex: `apache_2_4_49_rce.py`, create a config file with the same name but ending with `.ini` and place them in the `plugins/initial_access` directory. The config file should match the following format :

```ini
[DEFAULT]
plugin_name = <name of your plugin>
service = <name of the vulnerable service>
versions = <versions number>
extrainfo = <extra information>
http-title = <page title>
CVE = <CVE reference>
CVSS = <CVSS score>
```

* The plugin_name should be the exact same as your python file (case sensitive).
* The service name should be the same as the name returned by nmap (case sensitive).
* The versions number should have the same format that the one returned by nmap. You can specify mutliple versions numbers.
* The CVE reference and CVSS score are only used for the report available with --output <filename.md> option.

### Privesc plugins

Privesc scripts must be written in bash for linux targets and in .bat or .ps1 for windows targets.

## Licence

The following tool is under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public licence.

You are free to:

* **Share** — copy and redistribute the material in any medium or format
* **Adapt** — remix, transform, and build upon the material 

Under the following terms:

* **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **NonCommercial** — You may not use the material for commercial purposes.
* **ShareAlike** — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original. 

Please refer to the [licence](https://github.com/ip2root/ip2root/blob/master/COPYING.md).
