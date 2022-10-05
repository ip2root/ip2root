docker build -t apache-sudo .
docker run --name apache-sudo -d --ip 127.0.0.1 -p 4444:8080 apache-sudo httpd -D FOREGROUND
