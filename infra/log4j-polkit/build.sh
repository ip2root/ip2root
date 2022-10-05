docker build -t log4j-polkit .
docker run -p 5555:8080 --hostname victim log4j-polkit