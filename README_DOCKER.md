# 🐳 Neo4j Dashboard - Docker Setup

This project is containerized with Docker for easy deployment and development. Everything you need is pre-configured!

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) (version 20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (version 2.0+)

### 1. Clone the Repository
```bash
git clone https://github.com/omidvar1986/neo4j-dashboard.git
cd neo4j-dashboard
```

### 2. Start All Services
```bash
docker-compose up -d
```

### 3. Access the Application
- **Django App**: http://localhost:8000
- **Neo4j Browser**: http://localhost:7474
- **PostgreSQL**: localhost:5432

## 🔑 Default Credentials

### Django Admin User
- **Username**: `admin`
- **Password**: `admin123`
- **Role**: Admin (full access to all features)

### Database Credentials
- **PostgreSQL**:
  - Database: `neo_dashboard`
  - Username: `neo4j_dashboard_user`
  - Password: `Milad1986`
  - Host: `localhost` (from outside Docker)

- **Neo4j**:
  - Username: `neo4j`
  - Password: `Milad1986`
  - Host: `localhost` (from outside Docker)

## 🏗️ Architecture

The application consists of three main services:

### 1. **PostgreSQL** (`postgres`)
- **Port**: 5433
- **Purpose**: Django's primary database
- **Data Persistence**: Yes (Docker volume)
- **Health Check**: Automatic

### 2. **Neo4j** (`neo4j`)
- **Ports**: 7474 (HTTP), 7687 (Bolt)
- **Purpose**: Graph database for Neo4j operations
- **Data Persistence**: Yes (Docker volume)
- **Plugins**: APOC included
- **Health Check**: Automatic

### 3. **Django Web App** (`web`)
- **Port**: 8000
- **Purpose**: Main application server
- **Dependencies**: Waits for PostgreSQL and Neo4j
- **Auto-setup**: Migrations, admin user, static files

## 📁 Project Structure

```
neo4j-dashboard/
├── docker-compose.yml          # Main Docker orchestration
├── Dockerfile                  # Django app container
├── entrypoint.sh              # Container startup script
├── init_postgres.sql          # PostgreSQL initialization
├── requirements.txt            # Python dependencies
├── manage.py                  # Django management
├── neo4j_dashboard/          # Django project settings
├── dashboard/                 # Main Django app
└── README_DOCKER.md          # This file
```

## 🛠️ Useful Commands

### Start Services
```bash
# Start all services in background
docker-compose up -d

# Start with logs visible
docker-compose up

# Start specific service
docker-compose up postgres neo4j
```

### Stop Services
```bash
# Stop all services
docker-compose down

# Stop and remove volumes (⚠️ WARNING: Data loss!)
docker-compose down -v
```

### View Logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs web
docker-compose logs postgres
docker-compose logs neo4j

# Follow logs in real-time
docker-compose logs -f web
```

### Access Containers
```bash
# Django container
docker-compose exec web bash

# PostgreSQL container
docker-compose exec postgres psql -U neo4j_dashboard_user -d neo_dashboard

# Neo4j container
docker-compose exec neo4j cypher-shell -u neo4j -p Milad1986
```

### Database Operations
```bash
# Run Django migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Django shell
docker-compose exec web python manage.py shell
```

## 🔄 Data Persistence

### Volumes
- **PostgreSQL**: `postgres_data` - Database files
- **Neo4j**: `neo4j_data` - Graph database files
- **Logs**: `./logs` - Application logs
- **Static Files**: `./staticfiles` - Collected static files

### Backup
```bash
# PostgreSQL backup
docker-compose exec postgres pg_dump -U neo4j_dashboard_user neo_dashboard > backup.sql

# Neo4j backup (if needed)
docker-compose exec neo4j neo4j-admin dump --database=neo4j
```

## 🚨 Troubleshooting

### Common Issues

#### 1. **Port Already in Use**
```bash
# Check what's using the port
lsof -i :8000
lsof -i :5432
lsof -i :7474
lsof -i :7687

# Stop conflicting services
sudo systemctl stop postgresql
sudo systemctl stop neo4j
```

#### 2. **Container Won't Start**
```bash
# Check container logs
docker-compose logs web

# Check container status
docker-compose ps

# Restart specific service
docker-compose restart web
```

#### 3. **Database Connection Issues**
```bash
# Check if databases are running
docker-compose ps postgres neo4j

# Check database logs
docker-compose logs postgres
docker-compose logs neo4j

# Restart databases
docker-compose restart postgres neo4j
```

#### 4. **Permission Issues**
```bash
# Fix file permissions
chmod +x entrypoint.sh
chmod +x *.sh

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Reset Everything
```bash
# Complete reset (⚠️ WARNING: All data will be lost!)
docker-compose down -v
docker system prune -a
docker-compose up -d --build
```

## 🚀 Production Deployment

### Environment Variables
Create a `.env` file for production:
```env
DEBUG=False
SECRET_KEY=your-secure-secret-key-here
ALLOWED_HOSTS=your-domain.com,www.your-domain.com
POSTGRES_PASSWORD=your-secure-password
NEO4J_PASSWORD=your-secure-password
```

### Security Considerations
- Change default passwords
- Use strong SECRET_KEY
- Restrict ALLOWED_HOSTS
- Enable HTTPS
- Use production database credentials

## 📞 Support

If you encounter issues:

1. **Check the logs**: `docker-compose logs`
2. **Verify prerequisites**: Docker and Docker Compose versions
3. **Check ports**: Ensure no conflicts
4. **Review this README**: Common solutions above

## 🎯 What Happens on First Run

1. **PostgreSQL** starts and initializes database
2. **Neo4j** starts with APOC plugins
3. **Django** waits for both databases
4. **Migrations** run automatically
5. **Admin user** created: `admin/admin123`
6. **Static files** collected
7. **Application** starts on port 8000

## ✨ Features Ready Out of the Box

- ✅ **Complete Neo4j Dashboard** with all features
- ✅ **Admin user** with full access
- ✅ **PostgreSQL** database ready
- ✅ **Neo4j** graph database ready
- ✅ **All migrations** applied
- ✅ **Static files** collected
- ✅ **Health checks** for all services
- ✅ **Data persistence** across restarts

---

**🎉 You're all set!** Clone, run `docker-compose up -d`, and start using your Neo4j Dashboard!
