# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a WordPress AI Security Scanner Plugin - a portfolio project for a WordPress Support Engineer role. The plugin combines traditional security scanning with artificial intelligence to provide proactive threat detection, malware identification, and security hardening recommendations.

## Project Status

Phase 1 implementation is complete with full plugin functionality, comprehensive test suite, and documentation.

## Technical Architecture

### Core Components
- **Scanner Engine** - Multi-threaded scanning with queue management
- **AI Analysis Module** - Local ML inference with cloud API fallback  
- **Database Layer** - Custom tables for scan results and configuration
- **Admin Interface** - React-based dashboard with REST API backend
- **Notification System** - Email, SMS, and in-dashboard alerts

### WordPress Plugin Structure
- Standard WordPress plugin architecture following WordPress coding standards
- Custom database tables for scan results and threat intelligence
- REST API endpoints for dashboard functionality
- Background processing using WordPress cron system
- Role-based access control integration

### Technology Stack
- **Backend:** PHP 7.4+ (WordPress plugin)
- **Frontend:** React-based admin dashboard
- **Database:** MySQL 5.7+ with custom tables
- **AI/ML:** Lightweight models for local inference
- **Security:** AES-256 encryption, SSL/TLS communications

## Key Features (Implemented)

1. **AI-Powered Malware Detection** - ML models trained on malware patterns
2. **Smart Vulnerability Scanning** - OWASP Top 10 vulnerability detection
3. **File Integrity Monitoring** - Real-time file change detection with AI analysis
4. **Behavioral Analytics** - User behavior anomaly detection
5. **Automated Security Hardening** - One-click security fixes

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
- REST API development
- React integration within WordPress admin
- Security best practices implementation
- Machine learning model integration