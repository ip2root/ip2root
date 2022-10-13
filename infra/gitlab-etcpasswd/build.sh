sudo docker build -t gitlab-vuln . 
sudo docker run -p 2222:22 -p 6666:80 -p 4443:443 -it -d gitlab-vuln
