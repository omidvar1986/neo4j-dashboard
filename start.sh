#!/bin/bash

echo "🚀 Neo4j Dashboard - Docker Setup"
echo "=================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are available"

# Check if services are already running
if docker-compose ps | grep -q "Up"; then
    echo "⚠️  Services are already running!"
    echo "Current status:"
    docker-compose ps
    echo ""
    read -p "Do you want to restart the services? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🔄 Restarting services..."
        docker-compose down
        docker-compose up -d
    else
        echo "✅ Services are running. Access your application at:"
        echo "   🌐 Django App: http://localhost:8000"
        echo "   🗄️  Neo4j Browser: http://localhost:7474"
        echo "   🔑 Admin Login: admin / admin123"
        exit 0
    fi
else
    echo "🚀 Starting services..."
    docker-compose up -d
fi

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service status
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo "🌐 Django App: http://localhost:8000"
echo "🗄️  Neo4j Browser: http://localhost:7474"
echo "🔑 Admin Login: admin / admin123"
echo ""
echo "📋 Useful Commands:"
echo "   View logs: docker-compose logs -f"
echo "   Stop services: docker-compose down"
echo "   Restart: docker-compose restart"
echo ""
echo "🚀 Your Neo4j Dashboard is ready!"
