# Quick Deployment Reference

## Prerequisites Installation (One-time setup on VM)

```bash
# Connect to VM
ssh -i ./deployment_ssh_key miladomidvar@87.247.174.71

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
sudo apt-get update && sudo apt-get install -y git
```

## Deployment Steps

### 1. Clone Repository
```bash
cd ~
git clone YOUR_GITHUB_REPO_URL neo4j-dashboard
cd neo4j-dashboard
```

### 2. Update docker-compose.yml
Edit `docker-compose.yml` and update the `web` service environment:
```yaml
environment:
  - DEBUG=False
  - ALLOWED_HOSTS=87.247.174.71,localhost,127.0.0.1
  # ... keep other variables
```

### 3. Create Directories
```bash
mkdir -p logs staticfiles wiremock_mappings
```

### 4. Start Services
```bash
docker-compose up -d
```

### 5. Check Status
```bash
docker-compose ps
docker-compose logs -f
```

### 6. Run Migrations (if needed)
```bash
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py collectstatic --noinput
```

### 7. Create Admin User
```bash
docker-compose exec web python manage.py createsuperuser
```

## Access Your Application

- **Web App**: http://87.247.174.71:8000
- **Neo4j Browser**: http://87.247.174.71:7474
- **WireMock**: http://87.247.174.71:8081

## Common Commands

```bash
# View logs
docker-compose logs -f web

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Update application
git pull
docker-compose build web
docker-compose up -d web
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py collectstatic --noinput
```

## Firewall Setup (if needed)

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 7474/tcp
sudo ufw allow 7687/tcp
sudo ufw allow 8081/tcp
```

## Troubleshooting

```bash
# Check container status
docker ps

# Check specific service logs
docker-compose logs postgres
docker-compose logs neo4j
docker-compose logs web

# Check if ports are listening
sudo netstat -tlnp | grep 8000
```
