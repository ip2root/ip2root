docker build -t apache-sudo-2.4.49 .
docker run --name apache-sudo-2.4.49 -d --ip 127.0.0.1 -p 5555:8080 apache-sudo httpd -D FOREGROUND
