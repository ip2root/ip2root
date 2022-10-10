docker build -t apache-sudo-2.4.50 .
docker run --name apache-sudo-2.4.50 -d --ip 127.0.0.1 -p 4444:8080 apache-sudo httpd -D FOREGROUND
