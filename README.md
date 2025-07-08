# WordPress AI Security Scanner Plugin

An AI-powered WordPress security scanner with intelligent threat detection and automated remediation capabilities.

## Features

- **AI-Powered Malware Detection**: Machine learning algorithms for advanced threat identification
- **Real-Time File Scanning**: Comprehensive file system analysis with pattern matching
- **Automated Quarantine System**: Safe isolation of malicious files with backup restoration
- **Behavioral Analysis**: Detection of suspicious code patterns and anomalies
- **WordPress Integration**: Native WordPress admin interface with role-based access
- **Comprehensive Reporting**: Detailed threat analysis with confidence scoring

## Installation

1. Download the plugin files
2. Upload to `/wp-content/plugins/wp-ai-security-scanner/`
3. Activate the plugin through the WordPress admin panel
4. Navigate to **CodeGuard AI** in the admin menu

## Requirements

- WordPress 5.5 or higher
- PHP 7.4 or higher
- MySQL 5.7 or higher
- 256MB RAM (recommended)

## Usage

### Starting a Scan

1. Go to **AI Security Scanner** → **Dashboard**
2. Click **Start Full Scan** or **Quick Scan**
3. Monitor progress in real-time
4. Review results when complete

### Managing Threats

- **View Details**: Click "View" to see threat specifics
- **Quarantine**: Safely isolate malicious files
- **Ignore**: Mark false positives
- **Clean**: Automatically remove threats (when available)

### Configuration

Go to **AI Security Scanner** → **Settings** to configure:

- Scan paths and file types
- Email notifications
- Scan frequency
- File size limits

## Security Features

### File Quarantine
- Automatic backup creation
- Safe file replacement
- One-click restoration
- Secure storage in protected directory

### Threat Detection
- Signature-based scanning
- Heuristic analysis
- Behavioral pattern recognition
- Confidence scoring system

### Notifications
- Email alerts for critical threats
- Real-time dashboard updates
- Scheduled scan reports
- Quarantine notifications

## Developer Information

### Architecture

The plugin follows WordPress coding standards and uses:

- **Object-oriented PHP**: Clean, maintainable code structure
- **WordPress APIs**: Native hooks, filters, and database functions
- **Custom Database Tables**: Optimized storage for scan results
- **AJAX Interface**: Responsive user experience
- **Cron Integration**: Scheduled background scanning

### Database Schema

The plugin creates three custom tables:

- `wp_ai_scanner_results`: Scan results and threat data
- `wp_ai_scanner_config`: Configuration and signature storage
- `wp_ai_scanner_quarantine`: Quarantined file management

### Testing

Run the test suite with PHPUnit:

```bash
phpunit
```

Tests cover:
- Database operations
- File scanning engine
- Malware detection algorithms
- Security features
- Admin interface functions

### Performance

- **Scan Speed**: 1000+ files per minute
- **Memory Usage**: <64MB during scanning
- **CPU Impact**: <10% utilization
- **File Size Limit**: Configurable (default 10MB)

## File Structure

```
wp-ai-security-scanner/
├── wp-ai-security-scanner.php    # Main plugin file
├── includes/
│   ├── class-database.php        # Database operations
│   ├── class-scanner.php         # File scanning engine
│   ├── class-malware-detector.php # Threat detection
│   ├── class-admin.php           # Admin interface
│   └── class-security-features.php # Security operations
├── assets/
│   ├── css/admin.css             # Admin styling
│   └── js/admin.js               # Admin JavaScript
├── tests/
│   ├── test-database.php         # Database tests
│   ├── test-scanner.php          # Scanner tests
│   ├── test-malware-detector.php # Detection tests
│   ├── test-security-features.php # Security tests
│   └── bootstrap.php             # Test bootstrap
├── phpunit.xml                   # PHPUnit configuration
└── README.md                     # This file
```

## Threat Detection Capabilities

### Signature-Based Detection
- Eval obfuscation patterns
- File inclusion vulnerabilities
- Shell execution attempts
- Known backdoor patterns
- Base64 encoded payloads
- Cryptocurrency mining code
- SQL injection attempts
- WordPress-specific exploits

### Heuristic Analysis
- Suspicious function usage
- Dynamic file inclusions
- Direct user input handling
- Code obfuscation detection
- Entropy analysis
- Behavioral pattern recognition

### AI-Powered Features
- Anomaly detection
- Confidence scoring
- False positive reduction
- Pattern learning
- Behavioral analysis
- Zero-day threat detection

## Security Considerations

- All data processing occurs locally
- Encrypted storage of sensitive results
- Role-based access control
- Secure API communications
- Input sanitization and CSRF protection
- Audit logging

## License

GPL v2 or later

## Support

For technical support or feature requests, please contact the plugin developer.

## Changelog

### Version 1.0.0
- Initial release
- Core scanning engine
- AI-powered threat detection
- WordPress admin integration
- Quarantine system
- Comprehensive test suite