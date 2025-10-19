#!/bin/bash

# Wiremock Docker Setup Script
# This script sets up the holomekc/wiremock-gui Docker container

echo "🚀 Setting up Wiremock with GUI..."

# Create mappings directory if it doesn't exist
mkdir -p ./wiremock_mappings

# Stop and remove existing container if it exists
echo "🛑 Stopping existing Wiremock container..."
docker stop wiremock 2>/dev/null || true
docker rm wiremock 2>/dev/null || true

# Pull the latest image
echo "📥 Pulling holomekc/wiremock-gui image..."
docker pull holomekc/wiremock-gui

# Run the container with volume mapping for persistent mappings
echo "🏃 Starting Wiremock container..."
docker run -d \
  --name wiremock \
  -p 8080:8080 \
  -v $(pwd)/wiremock_mappings:/home/wiremock/mappings \
  holomekc/wiremock-gui

# Wait a moment for the container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check if container is running
if docker ps | grep -q wiremock; then
    echo "✅ Wiremock container is running!"
    echo ""
    echo "🌐 Access URLs:"
    echo "   - API: http://localhost:8080/__admin"
    echo "   - GUI: http://localhost:8080/__admin/webapp"
    echo "   - Mappings: http://localhost:8080/__admin/mappings"
    echo "   - Requests: http://localhost:8080/__admin/requests"
    echo ""
    echo "📁 Mappings will be saved to: ./wiremock_mappings/"
    echo ""
    echo "🔧 Management commands:"
    echo "   - Stop: docker stop wiremock"
    echo "   - Start: docker start wiremock"
    echo "   - Remove: docker rm -f wiremock"
    echo "   - Logs: docker logs wiremock"
else
    echo "❌ Failed to start Wiremock container"
    echo "Check Docker logs: docker logs wiremock"
    exit 1
fi
