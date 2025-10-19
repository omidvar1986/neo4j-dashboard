# Wiremock Management Integration

This Django application now includes comprehensive Wiremock management capabilities using the `holomekc/wiremock-gui` Docker image.

## 🚀 Quick Start

### 1. Setup Wiremock Container
```bash
# Run the setup script
./setup_wiremock.sh

# Or manually:
docker run -d --name wiremock -p 8080:8080 -v $(pwd)/wiremock_mappings:/home/wiremock/mappings holomekc/wiremock-gui
```

### 2. Access the Management Interface
- Navigate to **API Tools** in your Django dashboard
- Scroll down to the **Wiremock Management** section
- Use the three management cards:
  - **Server Management** - Monitor and control Docker container
  - **Stub Mappings** - Manage API mock mappings
  - **Request Logs** - Monitor API request logs

## 🎯 Features

### Docker Container Management
- **Start/Stop/Remove** Wiremock containers
- **Real-time status** monitoring
- **Automatic container creation** if not exists
- **Volume mapping** for persistent mappings

### Stub Mappings Management
- **View all mappings** with method badges and status
- **Create new mappings** with form interface
- **Delete mappings** with confirmation
- **View detailed JSON** for each mapping
- **Real-time updates** and refresh

### Request Logs Monitoring
- **Real-time request tracking**
- **Statistics dashboard** (total, success, errors)
- **Advanced filtering** by method, status, URL
- **Detailed request/response** JSON viewer
- **Timestamp and duration** tracking

### Web GUI Integration
- **Direct access** to Wiremock's web interface
- **One-click opening** in new tab
- **Seamless integration** with Django interface

## 🔧 Configuration

### Default URLs
- **API Base**: `http://localhost:8080`
- **Web GUI**: `http://localhost:8080/__admin/webapp`
- **Mappings API**: `http://localhost:8080/__admin/mappings`
- **Requests API**: `http://localhost:8080/__admin/requests`

### Docker Image
- **Image**: `holomekc/wiremock-gui`
- **Port**: `8080`
- **Volume**: `./wiremock_mappings` (for persistent mappings)

## 📋 API Endpoints

### Django Endpoints
- `GET /wiremock-server/` - Server management page
- `GET /wiremock-mappings/` - Mappings management page
- `GET /wiremock-logs/` - Request logs page
- `GET /wiremock-docker-status/` - Check container status
- `POST /wiremock-docker-start/` - Start container
- `POST /wiremock-docker-stop/` - Stop container
- `POST /wiremock-docker-remove/` - Remove container

### Wiremock API Integration
- `GET /wiremock-get-mappings/` - Get all mappings
- `GET /wiremock-get-logs/` - Get request logs
- `GET /wiremock-get-server-info/` - Get server info
- `POST /wiremock-create-mapping/` - Create new mapping
- `POST /wiremock-delete-mapping/` - Delete mapping

## 🛠️ Usage Examples

### 1. Start Wiremock Container
```bash
# Via Django interface: Click "Start Container" button
# Via command line:
docker run -d --name wiremock -p 8080:8080 holomekc/wiremock-gui
```

### 2. Create a Test Mapping
```bash
curl -X POST 'http://localhost:8080/__admin/mappings' \
  -H 'Content-Type: application/json' \
  -d '{
    "request": {
      "method": "GET",
      "urlPattern": "/api/test"
    },
    "response": {
      "status": 200,
      "headers": {
        "Content-Type": "application/json"
      },
      "body": "{\"message\": \"Hello from Wiremock!\"}"
    }
  }'
```

### 3. Test the Mapping
```bash
curl http://localhost:8080/api/test
# Response: {"message": "Hello from Wiremock!"}
```

## 🔍 Monitoring

### Container Status
- Real-time Docker container status
- Container ID, name, and status display
- Port mapping information
- Image version tracking

### Server Health
- API connectivity testing
- Server information display
- Settings and configuration viewer
- Error handling and reporting

### Request Analytics
- Total request count
- Success rate (2xx responses)
- Client errors (4xx responses)
- Server errors (5xx responses)
- Request filtering and search

## 🚨 Troubleshooting

### Container Won't Start
```bash
# Check Docker status
docker ps -a | grep wiremock

# Check logs
docker logs wiremock

# Remove and recreate
docker rm -f wiremock
./setup_wiremock.sh
```

### API Connection Issues
- Verify container is running: `docker ps | grep wiremock`
- Check port 8080 is available: `lsof -i :8080`
- Test API directly: `curl http://localhost:8080/__admin/settings`

### Permission Issues
- Ensure Docker is running: `docker --version`
- Check user permissions for Docker commands
- Verify port 8080 is not in use by another service

## 📁 File Structure

```
dashboard/
├── templates/dashboard/
│   ├── wiremock_server.html      # Server management page
│   ├── wiremock_mappings.html    # Mappings management page
│   └── wiremock_logs.html        # Request logs page
├── views.py                      # Django views and API endpoints
├── urls.py                       # URL patterns
└── setup_wiremock.sh            # Docker setup script
```

## 🔄 Updates and Maintenance

### Updating Wiremock
```bash
# Pull latest image
docker pull holomekc/wiremock-gui

# Recreate container
docker stop wiremock
docker rm wiremock
./setup_wiremock.sh
```

### Backup Mappings
```bash
# Mappings are automatically saved to ./wiremock_mappings/
# To backup:
cp -r ./wiremock_mappings ./wiremock_mappings_backup_$(date +%Y%m%d)
```

## 🎉 Benefits

1. **Unified Interface** - Manage Wiremock from your Django dashboard
2. **Docker Integration** - Easy container management
3. **Real-time Monitoring** - Live status and logs
4. **Web GUI Access** - Direct access to Wiremock's interface
5. **Persistent Storage** - Mappings survive container restarts
6. **User-friendly** - Intuitive interface for non-technical users

This integration makes Wiremock management seamless and accessible directly from your Django application!
