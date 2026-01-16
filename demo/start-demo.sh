#!/bin/bash

# WordPress AI Security Scanner Demo Startup Script

echo "🚀 Starting WordPress AI Security Scanner Demo Environment"
echo "=========================================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

find_free_port() {
    local port=$1
    while lsof -Pi :"$port" -sTCP:LISTEN -t >/dev/null 2>&1; do
        port=$((port + 1))
    done
    echo "$port"
}

WEB_PORT=$(find_free_port 8080)
PMA_PORT=$(find_free_port 8081)
export WEB_PORT PMA_PORT

if [ "$WEB_PORT" != "8080" ]; then
    echo "⚠️  Port 8080 in use; using $WEB_PORT instead."
fi

if [ "$PMA_PORT" != "8081" ]; then
    echo "⚠️  Port 8081 in use; using $PMA_PORT instead."
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
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEB_PORT}" 2>/dev/null | grep -qE "200|302|301"; then
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

echo "🛠️  Configuring WordPress with wp-cli..."
if docker-compose run --rm wp-cli core is-installed --path=/var/www/html --allow-root > /dev/null 2>&1; then
    echo "✅ WordPress already installed."
else
    docker-compose run --rm wp-cli core install --path=/var/www/html --url="http://localhost:${WEB_PORT}" --title="WordPress AI Security Scanner Demo" --admin_user=admin --admin_password=admin_password_123! --admin_email=admin@demo.local --skip-email --allow-root
fi

if docker-compose run --rm wp-cli plugin is-active wp-ai-security-scanner --path=/var/www/html --allow-root > /dev/null 2>&1; then
    echo "✅ wp-ai-security-scanner already active."
else
    docker-compose run --rm wp-cli plugin activate wp-ai-security-scanner --path=/var/www/html --allow-root
fi

if docker-compose run --rm wp-cli plugin is-active clean-demo-plugin --path=/var/www/html --allow-root > /dev/null 2>&1; then
    echo "✅ clean-demo-plugin already active."
else
    docker-compose run --rm wp-cli plugin activate clean-demo-plugin --path=/var/www/html --allow-root
fi

docker-compose run --rm wp-cli eval '
$settings = get_option("wp_ai_security_scanner_settings", array());
$settings["scan_paths"] = array(ABSPATH, ABSPATH . "wp-content/sample-threats");
$settings["use_openai"] = false;
$settings["openai_api_key"] = "";
$settings["use_virustotal"] = false;
$settings["virustotal_api_key"] = "";
update_option("wp_ai_security_scanner_settings", $settings);
' --path=/var/www/html --allow-root

# Check phpMyAdmin
echo "🔍 Checking phpMyAdmin..."
if curl -s -o /dev/null "http://localhost:${PMA_PORT}" 2>/dev/null; then
    echo "✅ phpMyAdmin is ready!"
else
    echo "⚠️  phpMyAdmin may still be starting up..."
fi

echo ""
echo "🎉 Demo environment is ready!"
echo ""
echo "📋 Access Information:"
echo "   WordPress:   http://localhost:${WEB_PORT}"
echo "   phpMyAdmin:  http://localhost:${PMA_PORT}"
echo ""
echo "🔐 Login Credentials:"
echo "   WordPress Admin: admin / admin_password_123!"
echo "   phpMyAdmin:      root / root_password"
echo ""
echo "📚 Next Steps:"
echo "   1. Log in at http://localhost:${WEB_PORT}/wp-admin"
echo "   2. Open 'AI Security Scanner' from the admin menu"
echo "   3. Click 'Start Full Scan' to begin"
echo ""
echo "🔍 Demo Features:"
echo "   - 13 sample threat files in wp-content/sample-threats/"
echo "   - Real-time scanning with progress updates"
echo "   - Threat detection and quarantine capabilities"
echo "   - Comprehensive admin dashboard"
echo ""
echo "📖 For detailed instructions, see demo/README.md"
echo ""
echo "🛑 To stop the demo: ./stop-demo.sh"