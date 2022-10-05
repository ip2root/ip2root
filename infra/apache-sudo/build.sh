docker build -t apache-polkit .
docker run --name apache-polkit -d --ip 127.0.0.1 -p 4444:8080 apache-polkit httpd -D FOREGROUND
