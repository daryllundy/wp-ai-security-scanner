# WordPress AI Security Scanner - Demo Environment

This Docker setup provides a complete WordPress environment for testing and demonstrating the WordPress AI Security Scanner plugin.

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Ports starting at 8080/8081 available (script auto-selects if busy)

### Optional: Override Defaults

Copy `.env.example` to `.env` to override ports or admin credentials:

```bash
cp .env.example .env
```

### 1. Start the Demo Environment

```bash
cd demo
./start-demo.sh
```

### 2. Log In

The startup script installs WordPress, activates the plugin, and configures settings automatically.

1. **Open WordPress**: Use the URL printed in your terminal (default http://localhost:8080)
2. **Log in** at `/wp-admin`:
   - Username: `admin`
   - Password: `admin_password_123!`
   - Email: `admin@demo.local`

OpenAI and VirusTotal integrations are disabled for this offline demo.

### 3. Run Your First Scan

1. Navigate to **AI Security Scanner** → **Dashboard**
2. Click **Start Full Scan** or **Quick Scan**
3. Watch the real-time progress
4. Review detected threats

### Reset the Demo

If you want a clean slate without rebuilding containers:

```bash
./reset-demo.sh
```

This resets the WordPress database and re-runs the automated setup.

## What's Included

### Services

- **WordPress 6.7** (PHP 8.3-FPM)
- **MySQL 8.0** database
- **Nginx** web server
- **phpMyAdmin** for database management
- **wp-cli** for automated setup

### Access Points

- **WordPress Site**: Use URL printed by `start-demo.sh` (default http://localhost:8080)
- **phpMyAdmin**: Use URL printed by `start-demo.sh` (default http://localhost:8081)
  - Username: `root`
  - Password: `root_password`

### Clean Reference Plugin

A safe reference plugin is preloaded and activated at `wp-content/plugins/clean-demo-plugin/`.

### Demo Malware Files

The environment includes 13 comprehensive sample threat files in `/wp-content/sample-threats/`:

#### Basic Threats
1. **eval-backdoor.php** - Base64 encoded eval patterns
2. **file-inclusion.php** - File inclusion vulnerabilities  
3. **shell-execution.php** - Shell command execution
4. **c99-shell.php** - Common backdoor shell patterns
5. **sql-injection.php** - SQL injection patterns
6. **wordpress-exploit.php** - WordPress-specific attacks
7. **obfuscated-malware.php** - Heavy obfuscation techniques
8. **clean-file.php** - Safe file (should not be detected)
9. **eicar.php** - Standard EICAR test string (benign)

#### Advanced Threats
10. **crypto-miner.php** - Comprehensive cryptocurrency mining (CoinHive, WebAssembly, hidden iframes)
11. **advanced-backdoor.php** - Multi-stage backdoor with 12 evasion techniques
12. **php-injection-suite.php** - 20 different injection attack vectors
13. **modern-malware-techniques.php** - Contemporary threats (fileless, anti-sandbox, persistence)

## Demo Scenarios

### Guided Demo Checklist

1. Log in to `/wp-admin` and open **AI Security Scanner** → **Dashboard**.
2. Run a **Quick Scan** to show immediate detections.
3. Open **Scan Results** and click **View** on a critical threat.
4. Quarantine one high-severity file and confirm its status.
5. Navigate to **Settings** and review scan paths and notifications.
6. Return to the dashboard and start a **Full Scan** for the long-form demo.

### Scenario 1: Basic Threat Detection

1. Navigate to **AI Security Scanner** → **Dashboard**
2. Click **Start Full Scan**
3. **Expected Results**:
   - 12+ threats detected in `/wp-content/sample-threats/`
   - Various severity levels (Critical, High, Medium, Low)
   - Confidence scores between 0.5-0.95
   - Multiple detection sources (Local, OpenAI, VirusTotal if configured)

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

### Scenario 5: AI Integration Testing

1. Go to **AI Security Scanner** → **Settings**
2. **Configure AI APIs** (optional):
   - Enable OpenAI integration
   - Enter OpenAI API key (sk-...)
   - Test API key connection
   - Enable VirusTotal integration  
   - Enter VirusTotal API key
   - Test API key connection
3. **Run enhanced scan** with AI analysis

### Scenario 6: Settings Configuration

1. Go to **AI Security Scanner** → **Settings**
2. **Configure options**:
   - Scan paths (includes `/wp-content/sample-threats/` by default)
   - File extensions
   - Email notifications
   - Scan frequency
   - AI-powered detection settings

## Technical Details

### File Structure

```
demo/
├── docker-compose.yml      # Main orchestration
├── nginx.conf             # Nginx configuration
├── default.conf           # Virtual host config
├── uploads.ini            # PHP upload settings
├── .env.example           # Optional overrides
├── clean-plugin/          # Safe demo plugin
├── sample-threats/        # Demo malware files (13 samples)
├── start-demo.sh         # Demo startup script
├── reset-demo.sh         # Demo reset script
├── stop-demo.sh          # Demo shutdown script
└── README.md             # This file
```

### Volume Mounts

- **Plugin Code**: `../` → `/var/www/html/wp-content/plugins/wp-ai-security-scanner`
- **Clean Plugin**: `./clean-plugin/` → `/var/www/html/wp-content/plugins/clean-demo-plugin`
- **Sample Threats**: `./sample-threats/` → `/var/www/html/wp-content/sample-threats`
- **WordPress Data**: `wordpress_data` volume
- **MySQL Data**: `mysql_data` volume

### Network Configuration

- **Internal network**: `wp-network`
- **WordPress → MySQL**: Port 3306
- **Nginx → WordPress**: Port 9000 (PHP-FPM)
- **External access**: Ports selected by `start-demo.sh` (defaults 8080 for web, 8081 for phpMyAdmin)

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
curl -X POST "http://localhost:<wordpress-port>/wp-admin/admin-ajax.php" \
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
# Stop services (preserves data)
./stop-demo.sh

# Stop services and remove all data
./stop-demo.sh -v

# Or use docker-compose directly
docker-compose down        # Stop containers
docker-compose down -v     # Stop and remove volumes

# Remove images (optional)
docker rmi $(docker images -q)
```