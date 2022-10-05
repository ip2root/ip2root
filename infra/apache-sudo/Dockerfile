FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install wget curl make gcc perl nano sudo -y
RUN apt-get install libapr1-dev libaprutil1-dev libpcre3-dev -y
RUN useradd -ms /bin/bash user_vuln -G sudo
WORKDIR /home/user_vuln
RUN sed -i '/^%sudo/d' /etc/sudoers
RUN echo "%sudo ALL=(ALL) NOPASSWD: /usr/bin/tar" >> /etc/sudoers
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.50.tar.gz
RUN tar -xf httpd-2.4.50.tar.gz
RUN ./httpd-2.4.50/configure --prefix=/
RUN make && make install
ADD httpd.conf /conf/httpd.conf
RUN chown -R user_vuln:user_vuln /logs
USER user_vuln
RUN apachectl -k start
