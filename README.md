# WordPress AI Security Scanner Plugin

An AI-powered WordPress security scanner with intelligent threat detection and automated remediation capabilities.

## Features

- **AI-Powered Malware Detection**: Local ML algorithms + OpenAI GPT-4 integration for advanced threat identification
- **VirusTotal Integration**: Cross-reference file hashes with global malware database
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
- **ML Training Pipeline**: Python-based machine learning for enhanced detection (see `/ml` directory)

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
│   ├── class-malware-detector.php # Threat detection (5-layer pipeline)
│   ├── class-admin.php           # Admin interface
│   └── class-security-features.php # Security operations
├── assets/
│   ├── css/admin.css             # Admin styling
│   └── js/admin.js               # jQuery-based admin interface
├── ml/                           # Machine Learning Pipeline
│   ├── training/                 # Model training scripts
│   │   ├── feature_extraction.py # PHP code feature engineering
│   │   ├── train_classifier.py   # Model training
│   │   └── evaluation.py         # Model evaluation
│   ├── inference/                # Inference server
│   │   └── inference_server.py   # REST API for predictions
│   └── README.md                 # ML pipeline documentation
├── docs/
│   ├── ML_ARCHITECTURE.md        # ML system design documentation
│   └── ALGORITHM_DOCUMENTATION.md # Detection algorithm details
├── demo/
│   ├── sample-threats/           # 12 realistic malware samples
│   └── docker-compose.yml        # Demo environment
├── tests/
│   ├── test-database.php         # Database tests
│   ├── test-scanner.php          # Scanner tests
│   ├── test-malware-detector.php # Detection tests (50+ tests)
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

**Current Implementation (PHP Runtime):**
- **Entropy Analysis**: Shannon entropy calculation to detect encrypted/obfuscated code
- **Behavioral Scoring**: Cumulative risk scoring based on suspicious patterns
- **Obfuscation Detection**: Multi-factor scoring for code obfuscation
- **OpenAI GPT-4 Integration**: Advanced code analysis with natural language understanding (optional)
- **VirusTotal API**: Hash-based malware verification with 70+ antivirus engines (optional)
- **Confidence Scoring**: Multi-source threat validation with severity ranking

**ML Training Pipeline (Python - see `/ml` directory):**
- **Feature Engineering**: 100+ features extracted from PHP code
- **Model Training**: Random Forest, XGBoost, and Neural Network classifiers
- **Model Export**: ONNX format for cross-platform inference
- **REST API Server**: Flask-based inference server for integration

## Security Considerations

- **Local processing**: Primary analysis occurs locally for privacy
- **API Security**: Secure API communications with OpenAI and VirusTotal (optional)
- **Data Protection**: Encrypted storage of sensitive results and API keys
- **Access Control**: Role-based access control with WordPress capabilities
- **Input Validation**: Comprehensive sanitization and CSRF protection
- **Audit Logging**: Complete activity tracking for security events

### API Integration Security

- **API Keys**: Stored securely in WordPress options with encryption
- **Rate Limiting**: Automatic throttling to prevent API abuse
- **Error Handling**: Graceful degradation when APIs are unavailable
- **Privacy**: File contents sent to APIs only when locally flagged as suspicious
- **Validation**: Real-time API key validation and testing

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