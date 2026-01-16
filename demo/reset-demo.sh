#!/bin/bash

# WordPress AI Security Scanner Demo Reset Script

echo "🔄 Resetting WordPress AI Security Scanner Demo"
echo "================================================"

if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "📦 Ensuring Docker containers are running..."
docker-compose up -d

port_output=$(docker-compose port nginx 80 2>/dev/null)
if [ -z "$port_output" ]; then
    WEB_PORT=8080
else
    WEB_PORT=${port_output##*:}
fi

WP_ADMIN_USER=${WP_ADMIN_USER:-admin}
WP_ADMIN_PASSWORD=${WP_ADMIN_PASSWORD:-admin_password_123!}
WP_ADMIN_EMAIL=${WP_ADMIN_EMAIL:-admin@demo.local}
WP_SITE_TITLE=${WP_SITE_TITLE:-WordPress AI Security Scanner Demo}

echo "🧹 Resetting WordPress database..."
docker-compose run --rm wp-cli db reset --yes --path=/var/www/html --allow-root

echo "🛠️  Reinstalling WordPress..."
docker-compose run --rm wp-cli core install --path=/var/www/html --url="http://localhost:${WEB_PORT}" --title="$WP_SITE_TITLE" --admin_user="$WP_ADMIN_USER" --admin_password="$WP_ADMIN_PASSWORD" --admin_email="$WP_ADMIN_EMAIL" --skip-email --allow-root

docker-compose run --rm wp-cli plugin activate wp-ai-security-scanner --path=/var/www/html --allow-root
docker-compose run --rm wp-cli plugin activate clean-demo-plugin --path=/var/www/html --allow-root

docker-compose run --rm wp-cli eval '
$settings = get_option("wp_ai_security_scanner_settings", array());
$settings["scan_paths"] = array(ABSPATH, ABSPATH . "wp-content/sample-threats");
$settings["use_openai"] = false;
$settings["openai_api_key"] = "";
$settings["use_virustotal"] = false;
$settings["virustotal_api_key"] = "";
update_option("wp_ai_security_scanner_settings", $settings);
' --path=/var/www/html --allow-root

echo "✅ Demo reset complete. Log in at http://localhost:${WEB_PORT}/wp-admin"
