docker build -t apache-vuln .
docker run --name apache-vuln -d -p 4444:80 apache-vuln httpd -D FOREGROUND
