# WordPress AI Security Scanner - Demo Environment

This Docker setup provides a complete WordPress environment for testing and demonstrating the WordPress AI Security Scanner plugin.

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Ports 8080 and 8081 available on your system

### 1. Start the Demo Environment

```bash
cd demo
./start-demo.sh
```

### 2. Setup WordPress

1. **Open WordPress**: http://localhost:8080
2. **Complete WordPress installation**:
   - Site Title: `WordPress AI Security Scanner Demo`
   - Username: `admin`
   - Password: `admin_password_123!`
   - Email: `admin@demo.local`

### 3. Activate the Plugin

1. Go to **Plugins** → **Installed Plugins**
2. Find "WordPress AI Security Scanner"
3. Click **Activate**

### 4. Run Your First Scan

1. Navigate to **AI Security Scanner** → **Dashboard**
2. Click **Start Full Scan** or **Quick Scan**
3. Watch the real-time progress
4. Review detected threats

## What's Included

### Services

- **WordPress 6.4** (PHP 8.2-FPM)
- **MySQL 8.0** database
- **Nginx** web server
- **phpMyAdmin** for database management

### Access Points

- **WordPress Site**: http://localhost:8080
- **phpMyAdmin**: http://localhost:8081
  - Username: `root`
  - Password: `root_password`

### Demo Malware Files

The environment includes 9 sample threat files in `/wp-content/sample-threats/`:

1. **eval-backdoor.php** - Base64 encoded eval patterns
2. **file-inclusion.php** - File inclusion vulnerabilities
3. **shell-execution.php** - Shell command execution
4. **c99-shell.php** - Common backdoor shell patterns
5. **crypto-miner.php** - Cryptocurrency mining code
6. **obfuscated-malware.php** - Heavy obfuscation techniques
7. **sql-injection.php** - SQL injection patterns
8. **wordpress-exploit.php** - WordPress-specific attacks
9. **clean-file.php** - Safe file (should not be detected)

## Demo Scenarios

### Scenario 1: Basic Threat Detection

1. Navigate to **AI Security Scanner** → **Dashboard**
2. Click **Start Full Scan**
3. **Expected Results**:
   - 8 threats detected in `/wp-content/sample-threats/`
   - Various severity levels (Critical, High, Medium)
   - Confidence scores between 0.6-0.9

### Scenario 2: Quick Scan

1. Click **Quick Scan** for faster results
2. **Expected Results**:
   - Focuses on high-risk directories
   - Faster completion (30-60 seconds)
   - Detects sample threats immediately

### Scenario 3: Threat Analysis

1. Go to **AI Security Scanner** → **Scan Results**
2. **Review threat details**:
   - Click "View" on any threat
   - Examine confidence scores
   - Review threat descriptions
   - Check file paths and line numbers

### Scenario 4: File Quarantine

1. From **Scan Results**, select a critical threat
2. Click **Quarantine**
3. **Verify quarantine**:
   - File content replaced with safe placeholder
   - Original file backed up securely
   - Status updated to "Quarantined"

### Scenario 5: Settings Configuration

1. Go to **AI Security Scanner** → **Settings**
2. **Configure options**:
   - Scan paths (add `/wp-content/sample-threats/`)
   - File extensions
   - Email notifications
   - Scan frequency

## Technical Details

### File Structure

```
demo/
├── docker-compose.yml      # Main orchestration
├── nginx.conf             # Nginx configuration
├── default.conf           # Virtual host config
├── uploads.ini            # PHP upload settings
├── sample-threats/        # Demo malware files
├── start-demo.sh         # Demo startup script
└── README.md             # This file
```

### Volume Mounts

- **Plugin Code**: `../` → `/var/www/html/wp-content/plugins/wp-ai-security-scanner`
- **Sample Threats**: `./sample-threats/` → `/var/www/html/wp-content/sample-threats`
- **WordPress Data**: `wordpress_data` volume
- **MySQL Data**: `mysql_data` volume

### Network Configuration

- **Internal network**: `wp-network`
- **WordPress → MySQL**: Port 3306
- **Nginx → WordPress**: Port 9000 (PHP-FPM)
- **External access**: Port 8080 (web), 8081 (phpMyAdmin)

## Advanced Testing

### Performance Testing

1. **Time a full scan** of WordPress installation
2. **Monitor resource usage**:
   - Memory consumption
   - CPU utilization
   - Scan speed (files per minute)

### API Testing

Test AJAX endpoints directly:

```bash
# Start scan via curl
curl -X POST "http://localhost:8080/wp-admin/admin-ajax.php" \
  -d "action=start_scan&nonce=YOUR_NONCE" \
  -H "Cookie: wordpress_logged_in_cookie=YOUR_COOKIE"
```

### Performance Monitoring

```bash
# Monitor scan performance
docker exec wp-security-scanner-wp top -p $(pgrep php)
```

## Troubleshooting

### Plugin Not Visible

```bash
# Check plugin files are mounted correctly
docker exec wp-security-scanner-wp ls -la /var/www/html/wp-content/plugins/
```

### Database Connection Issues

```bash
# Check MySQL status
docker-compose logs mysql

# Restart services
docker-compose restart
```

### Permission Issues

```bash
# Fix WordPress permissions
docker exec wp-security-scanner-wp chown -R www-data:www-data /var/www/html
```

### Clear Everything

```bash
# Stop and remove all containers, volumes, and networks
docker-compose down -v
docker system prune -f
```

## Security Notes

⚠️ **Demo Environment Only**: This setup is for demonstration purposes only and should not be used in production.

- Default passwords are used
- Debug mode is enabled
- Sample malware files are included
- No SSL/TLS encryption
- Permissive security settings

## Cleanup

When finished with the demo:

```bash
# Stop services
docker-compose down

# Remove volumes (optional)
docker-compose down -v

# Remove images (optional)
docker rmi $(docker images -q)
```