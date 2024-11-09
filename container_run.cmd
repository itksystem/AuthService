docker pull itksystem/auth-service
docker run -d --name auth-service --restart unless-stopped -p 3001:3001 -p 5672:5672 -p 443:443 --env-file .env.prod itksystem/auth-service


