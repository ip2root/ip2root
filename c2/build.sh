docker run -it -d -p 1337:1337 -p 5000:5000 -p 8888:8888 --name empire bcsecurity/empire:latest
curl -L https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage -o /tmp/starkiller
chmod +x /tmp/starkiller
token=$(curl https://localhost:1337/api/admin/login -s --insecure -H "Content-Type: application/json" -X POST -d '{"username":"empireadmin", "password":"password123"}' | cut -d'"' -f4)
curl --insecure -i -H "Content-Type: application/json" https://localhost:1337/api/listeners/http\?token\=$token -X POST -d '{"Name":"CLIHTTP", "Port":"8888"}'
./tmp/starkiller &
