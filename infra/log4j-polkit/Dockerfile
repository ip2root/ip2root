FROM ubuntu
COPY --chown=www-data:www-data spring-boot-application.jar /app/spring-boot-application.jar
RUN apt update
RUN apt install -y net-tools curl wget gcc netcat-traditional
RUN echo "deb http://archive.ubuntu.com/ubuntu/ impish main universe\ndeb http://archive.ubuntu.com/ubuntu/ bionic universe" >> /etc/apt/sources.list
RUN apt update
RUN apt install -y openjdk-8-jdk=8u162-b12-1 openjdk-8-jre=8u162-b12-1 openjdk-8-jdk-headless=8u162-b12-1 openjdk-8-jre-headless=8u162-b12-1
RUN apt install -y policykit-1=0.105-31
RUN chown -R www-data:www-data /app
USER www-data 
RUN echo "java -jar /app/spring-boot-application.jar" > /app/start.sh
RUN chmod +x /app/start.sh
ENTRYPOINT /bin/bash /app/start.sh