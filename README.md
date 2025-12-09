# WordPress AI Security Scanner Plugin

**Production-ready WordPress plugin for AI-powered security scanning and threat detection.**

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/daryllundy/wp-ai-security-scanner/releases/tag/v1.1.0)
[![WordPress](https://img.shields.io/badge/WordPress-5.5%2B-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-GPL%20v2-green.svg)](LICENSE)

An AI-powered WordPress security scanner with intelligent threat detection and automated remediation capabilities. Combines traditional security scanning with artificial intelligence to provide proactive threat detection, malware identification, and security hardening recommendations.

## Quick Start

### Download & Install from GitHub Releases

**Recommended method for production use:**

1. **Download the latest release:**
   - Go to [Releases](https://github.com/daryllundy/wp-ai-security-scanner/releases/latest)
   - Download `wp-ai-security-scanner-v1.1.0.zip`

2. **Install via WordPress Admin:**
   - Log in to your WordPress admin panel
   - Go to **Plugins → Add New → Upload Plugin**
   - Click **Choose File** and select the downloaded zip file
   - Click **Install Now**
   - Click **Activate Plugin**

3. **Access the plugin:**
   - Navigate to **AI Security Scanner** in the admin menu
   - Start your first security scan!

### Alternative Installation Methods

**Manual Installation:**
```bash
cd /path/to/wordpress/wp-content/plugins/
unzip wp-ai-security-scanner-v1.1.0.zip
```
Then activate through WordPress admin panel.

**Development Installation:**
```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/daryllundy/wp-ai-security-scanner.git
```
Then activate through WordPress admin panel.

## Features

### Core Security Capabilities
- 🤖 **AI-Powered Malware Detection** - 5-layer detection pipeline with entropy analysis, heuristics, and optional cloud AI
- 🔍 **Smart Vulnerability Scanning** - Pattern-based detection of OWASP top 10 vulnerabilities
- 📊 **File Integrity Monitoring** - Hash-based file change detection with confidence scoring
- 🧠 **Behavioral Analysis** - Code behavior pattern recognition for WordPress-specific threats
- 🔒 **Automated Quarantine System** - Safe file isolation with backup and restoration
- ⚡ **Real-Time Scanning** - Comprehensive file system analysis with live progress tracking
- 📈 **Comprehensive Reporting** - Detailed threat analysis with severity rankings

### Security & Privacy
- 🔐 **AES-256-CBC Encryption** - Secure storage of API keys and sensitive data
- 🛡️ **Rate Limiting** - Automatic throttling for external API calls
- 📝 **Audit Logging** - Complete security event tracking and activity monitoring
- 🏠 **Privacy-First** - All primary analysis occurs locally
- ✅ **CSRF Protection** - Input sanitization and WordPress nonce verification
- 🔑 **Role-Based Access** - Integration with WordPress capability system

### Performance
- ⚡ Scans **1000+ files per minute**
- 💾 Memory usage **< 64MB** during active scanning
- 🎯 CPU impact **< 10%** utilization during background scans
- ⏱️ Dashboard load time **< 2 seconds**

## Requirements

- WordPress 5.5 or higher
- PHP 7.4 or higher
- MySQL 5.7 or higher
- 256MB RAM (recommended)

## API Integration Setup (Optional)

The plugin supports optional AI-powered analysis through external APIs:

### OpenAI Integration

1. Get an API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Go to **AI Security Scanner** → **Settings**
3. Enable "OpenAI Integration"
4. Enter your API key
5. Click "Test API Key" to verify

**Benefits:**
- Advanced code analysis with GPT-4
- Natural language threat descriptions
- Context-aware malware detection
- Enhanced zero-day threat identification

**Cost:** ~$0.01-0.03 per file analyzed (pay-per-use)

### VirusTotal Integration

1. Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Go to **AI Security Scanner** → **Settings**
3. Enable "VirusTotal Integration"
4. Enter your API key
5. Click "Test API Key" to verify

**Benefits:**
- Hash-based malware verification
- Global threat intelligence database
- Multi-engine malware detection
- Known threat identification

**Limits:** Free tier includes 1000 requests/day

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
- OpenAI API integration
- VirusTotal API integration

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
- **jQuery-based Admin UI**: Responsive AJAX interface with real-time updates
- **Cron Integration**: Scheduled background scanning

### Database Schema

The plugin creates four custom tables:

- `wp_ai_scanner_results`: Scan results and threat data
- `wp_ai_scanner_config`: Configuration and signature storage
- `wp_ai_scanner_quarantine`: Quarantined file management
- `wp_ai_scanner_audit_log`: Security audit trail and activity logging

### Testing

**Full test suite with 83 tests** covering all major functionality.

Run the test suite with PHPUnit:

```bash
# Install development dependencies first (if needed)
composer install --dev

# Run all tests
phpunit

# Run specific test file
phpunit tests/test-malware-detector.php

# Run with coverage report
phpunit --coverage-html coverage/
```

**Test Coverage:**
- Database operations (7 tests)
- File scanning engine (10 tests)
- Malware detection algorithms (29 tests)
- Security features including encryption and rate limiting (13 tests)
- Enhanced scanner functionality (12 tests)
- Admin API integration (12 tests)

All tests use WordPress test framework and mock WordPress functions for unit testing.

### Performance

- **Scan Speed**: 1000+ files per minute
- **Memory Usage**: <64MB during scanning
- **CPU Impact**: <10% utilization
- **File Size Limit**: Configurable (default 10MB)

## Plugin File Structure

**Production Release Structure:**
```
wp-ai-security-scanner/
├── wp-ai-security-scanner.php    # Main plugin file
├── includes/
│   ├── class-database.php        # Database operations
│   ├── class-scanner.php         # File scanning engine
│   ├── class-malware-detector.php # Threat detection (multi-layer pipeline)
│   ├── class-admin.php           # Admin interface
│   └── class-security-features.php # Security operations (encryption, rate limiting)
├── assets/
│   ├── css/admin.css             # Admin styling
│   └── js/admin.js               # jQuery-based admin interface
├── docs/
│   └── ALGORITHM_DOCUMENTATION.md # Detection algorithm details
└── README.md                     # Documentation
```

**Development Repository Structure:**

The full repository includes additional development files:
- `demo/` - Docker-based demo environment with sample threats
- `tests/` - PHPUnit test suite (83 tests across 6 test files)
- `phpunit.xml` - Test configuration

These files are excluded from the production release zip.

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

**Detection Capabilities:**
- **Entropy Analysis**: Shannon entropy calculation to detect encrypted/obfuscated code
- **Behavioral Scoring**: Cumulative risk scoring based on suspicious patterns
- **Obfuscation Detection**: Multi-factor scoring for code obfuscation
- **OpenAI GPT-4 Integration**: Advanced code analysis with natural language understanding (optional)
- **VirusTotal API**: Hash-based malware verification with 70+ antivirus engines (optional)
- **Confidence Scoring**: Multi-source threat validation with severity ranking

## Security Considerations

- **Local processing**: Primary analysis occurs locally for privacy
- **API Security**: Secure API communications with OpenAI and VirusTotal (optional)
- **Data Protection**: AES-256-CBC encryption for API keys with secure key generation
- **Access Control**: Role-based access control with WordPress capabilities
- **Input Validation**: Comprehensive sanitization and CSRF protection
- **Audit Logging**: Complete activity tracking for security events (scan events, threats, quarantine actions, settings changes)

### API Integration Security

- **API Keys**: Stored with AES-256-CBC encryption in WordPress options
- **Rate Limiting**: Automatic throttling (20 req/min OpenAI, 4 req/min VirusTotal)
- **Error Handling**: Graceful degradation when APIs are unavailable or rate limited
- **Privacy**: File contents sent to APIs only when locally flagged as suspicious
- **Validation**: Real-time API key validation and testing

## License

GPL v2 or later

## Support

For technical support or feature requests, please contact the plugin developer.

## Project Status

✅ **Phase 1: Complete** - Full plugin functionality with comprehensive test suite

The plugin is production-ready and suitable for:
- Portfolio demonstration of WordPress development skills
- Real-world security scanning (with appropriate precautions)
- Educational purposes and security research
- Small to medium WordPress installations

**Test Coverage:**
- 83 tests across 6 test files
- Database operations (7 tests)
- Scanner engine (10 tests)
- Malware detection (29 tests)
- Security features (13 tests)
- Enhanced scanning (12 tests)
- Admin API integration (12 tests)

**Demo Environment:**
- Docker-based WordPress installation
- 12 realistic malware samples for testing
- Pre-configured demo data

## Contributing & Development

This project is part of a portfolio for a WordPress Support Engineer role. While it's a personal portfolio project, issues and suggestions are welcome.

**Development Setup:**
```bash
# Clone the repository
git clone https://github.com/daryllundy/wp-ai-security-scanner.git
cd wp-ai-security-scanner

# Run tests
phpunit

# Start demo environment
cd demo
docker-compose up -d
```

For detailed algorithm documentation, see [docs/ALGORITHM_DOCUMENTATION.md](docs/ALGORITHM_DOCUMENTATION.md).

## Changelog

### [Version 1.1.0](https://github.com/daryllundy/wp-ai-security-scanner/releases/tag/v1.1.0) - 2025-12-08
- ✨ Added AES-256-CBC encryption for API key storage
- 🛡️ Added rate limiting for external API calls (OpenAI: 20 req/min, VirusTotal: 4 req/min)
- 📝 Added comprehensive audit logging system
- 🗄️ Added audit log database table
- 🔒 Improved security event tracking
- 📚 Updated test coverage documentation
- 🎁 **First official release** with production-ready zip file

### Version 1.0.0 - Initial Development
- Core scanning engine
- AI-powered threat detection
- WordPress admin integration
- Quarantine system
- Comprehensive test suite

## Download

**Latest Release:** [v1.1.0](https://github.com/daryllundy/wp-ai-security-scanner/releases/tag/v1.1.0)

Download the production-ready plugin: [wp-ai-security-scanner-v1.1.0.zip](https://github.com/daryllundy/wp-ai-security-scanner/releases/download/v1.1.0/wp-ai-security-scanner-v1.1.0.zip)