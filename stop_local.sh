#!/bin/bash

echo "🛑 Stopping Neo4j Dashboard..."

# Stop Docker containers
if docker ps | grep -q "neo4j_dashboard_postgres\|neo4j_dashboard_neo4j"; then
    echo "📦 Stopping Docker containers..."
    docker-compose stop postgres neo4j 2>/dev/null || docker compose stop postgres neo4j 2>/dev/null
    echo "✅ Docker containers stopped"
else
    echo "ℹ️  Docker containers are not running"
fi

echo ""
echo "✅ All services stopped"
echo ""
echo "To start again, run: ./run_local.sh"
echo "To remove containers and data, run: docker-compose down -v"

