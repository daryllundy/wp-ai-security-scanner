#!/bin/bash

# WordPress AI Security Scanner Demo Startup Script

echo "🚀 Starting WordPress AI Security Scanner Demo Environment"
echo "=========================================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if ports are available
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "❌ Error: Port 8080 is already in use. Please free the port and try again."
    exit 1
fi

if lsof -Pi :8081 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "❌ Error: Port 8081 is already in use. Please free the port and try again."
    exit 1
fi

echo "📦 Starting Docker containers..."
docker-compose up -d

# Wait for MySQL to be healthy
echo "⏳ Waiting for MySQL to be ready..."
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if docker-compose ps mysql | grep -q "healthy"; then
        echo "✅ MySQL is healthy!"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    printf "."
done
echo ""

if [ $elapsed -ge $timeout ]; then
    echo "⚠️  MySQL health check timed out, continuing anyway..."
fi

# Wait for WordPress to respond
echo "⏳ Waiting for WordPress to start..."
timeout=30
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null | grep -qE "200|302|301"; then
        echo "✅ WordPress is ready!"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    printf "."
done
echo ""

if [ $elapsed -ge $timeout ]; then
    echo "⚠️  WordPress may still be starting up..."
fi

# Check phpMyAdmin
echo "🔍 Checking phpMyAdmin..."
if curl -s -o /dev/null http://localhost:8081 2>/dev/null; then
    echo "✅ phpMyAdmin is ready!"
else
    echo "⚠️  phpMyAdmin may still be starting up..."
fi

echo ""
echo "🎉 Demo environment is ready!"
echo ""
echo "📋 Access Information:"
echo "   WordPress:   http://localhost:8080"
echo "   phpMyAdmin:  http://localhost:8081"
echo ""
echo "🔐 Login Credentials:"
echo "   WordPress Admin: admin / admin_password_123!"
echo "   phpMyAdmin:      root / root_password"
echo ""
echo "📚 Next Steps:"
echo "   1. Complete WordPress setup at http://localhost:8080"
echo "   2. Activate the 'WordPress AI Security Scanner' plugin"
echo "   3. Navigate to 'AI Security Scanner' in the admin menu"
echo "   4. Run your first security scan!"
echo ""
echo "🔍 Demo Features:"
echo "   - 12 sample threat files in wp-content/sample-threats/"
echo "   - Real-time scanning with progress updates"
echo "   - Threat detection and quarantine capabilities"
echo "   - Comprehensive admin dashboard"
echo ""
echo "📖 For detailed instructions, see demo/README.md"
echo ""
echo "🛑 To stop the demo: ./stop-demo.sh"