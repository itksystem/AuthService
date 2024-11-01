docker pull itksystem/auth-service
docker run -d --name auth-service --restart unless-stopped -p 3000:3000 -p 5672:5672 -p 443:443 --env-file .env itksystem/auth-service


