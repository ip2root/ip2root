docker build -t apache-vuln .
docker run --name apache-vuln -d --ip 127.0.0.1 -p 4444:8080 apache-vuln httpd -D FOREGROUND
