# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a WordPress AI Security Scanner Plugin - a portfolio project for a WordPress Support Engineer role. The plugin combines traditional security scanning with artificial intelligence to provide proactive threat detection, malware identification, and security hardening recommendations.

## Project Status

Phase 1 implementation is complete with full plugin functionality, comprehensive test suite, and documentation.

## Technical Architecture

### Core Components
- **Scanner Engine** - File scanning with queue management and progress tracking
- **AI Analysis Module** - Multi-layer detection pipeline (signatures → heuristics → statistics → OpenAI → VirusTotal)
- **Database Layer** - Custom tables for scan results and configuration
- **Admin Interface** - jQuery-based dashboard with AJAX backend
- **Notification System** - Email and in-dashboard alerts

### WordPress Plugin Structure
- Standard WordPress plugin architecture following WordPress coding standards
- Custom database tables for scan results and threat intelligence
- REST API endpoints for dashboard functionality
- Background processing using WordPress cron system
- Role-based access control integration

### Technology Stack
- **Backend:** PHP 7.4+ (WordPress plugin)
- **Frontend:** jQuery-based admin dashboard with AJAX
- **Database:** MySQL 5.7+ with custom tables
- **AI/ML:** Entropy analysis, heuristic scoring, behavioral patterns
- **External APIs:** OpenAI GPT-4, VirusTotal (optional)
- **Security:** AES-256 encryption, SSL/TLS communications

## Key Features (Implemented)

1. **AI-Powered Malware Detection** - 5-layer detection pipeline with entropy analysis, heuristics, and optional cloud AI
2. **Smart Vulnerability Scanning** - Pattern-based detection of OWASP vulnerabilities
3. **File Integrity Monitoring** - Hash-based file change detection with confidence scoring
4. **Behavioral Analysis** - Code behavior pattern recognition (WordPress DB manipulation, admin creation, etc.)
5. **Automated Quarantine System** - Safe file isolation with backup and restoration

## Performance Requirements

- Scan speed: 1000+ files per minute
- Memory usage: < 64MB during active scanning
- CPU impact: < 10% utilization during background scans
- Dashboard load time: < 2 seconds

## WordPress Compatibility

- WordPress 5.5+ (support for latest 3 major versions)
- PHP 7.4+ (PHP 8.0+ recommended)
- MySQL 5.7+ or MariaDB 10.3+
- Minimum 128MB memory, recommended 256MB

## Security Considerations

- All data processing occurs locally (privacy-first approach)
- Encrypted storage of sensitive scan results
- Input sanitization and CSRF protection
- Secure API communications with SSL/TLS
- Role-based access control integration

## Development Notes

This project demonstrates advanced WordPress plugin development skills including:
- Custom database schema design
- Background processing and queue management
- AJAX-based admin interface development
- Security best practices implementation (nonces, prepared statements, sanitization)
- AI-powered threat detection with entropy analysis and behavioral scoring
- External API integration (OpenAI, VirusTotal)
- Comprehensive test suite (180+ tests with 1:1 test-to-code ratio)

## Documentation

- `docs/ALGORITHM_DOCUMENTATION.md` - Detailed detection algorithm documentation