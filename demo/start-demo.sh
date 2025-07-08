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

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 15

# Check if WordPress is responding
echo "🔍 Checking service health..."
if curl -s http://localhost:8080 > /dev/null; then
    echo "✅ WordPress is ready!"
else
    echo "⚠️  WordPress may still be starting up..."
fi

if curl -s http://localhost:8081 > /dev/null; then
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
echo "   - 9 sample threat files in wp-content/sample-threats/"
echo "   - Real-time scanning with progress updates"
echo "   - Threat detection and quarantine capabilities"
echo "   - Comprehensive admin dashboard"
echo ""
echo "📖 For detailed instructions, see demo/README.md"
echo ""
echo "🛑 To stop the demo: docker-compose down"