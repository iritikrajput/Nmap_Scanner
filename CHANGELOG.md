# Changelog

All notable changes to Security Scanner Suite will be documented in this file.

## [1.1.0] - 2024-12-16

### ✨ New Features

- **Multi-format Report Output**
  - XML format report (`report_*.xml`)
  - TXT format report (`report_*.txt`)
  - JSON format report (`report_*.json`)
  - All three formats generated automatically

- **HTTPS Security Prioritization**
  - HTTPS URLs checked before HTTP
  - HSTS validation on HTTPS connections
  - HTTP→HTTPS redirect detection
  - SSL stripping vulnerability detection

### 🔧 Improvements

- Enhanced security header checking for HTTPS
- Better HSTS validation (max-age, includeSubDomains, preload)
- CSP analysis for unsafe-inline and unsafe-eval
- Improved risk scoring for HTTPS-specific issues

---

## [1.0.0] - 2024-12-16

### 🎉 Initial Release

#### Intelligent Scanner (`intelligent_scanner.py`)

- **Phase 1: Nmap Reconnaissance**
  - Port scanning with service detection
  - SSL/TLS certificate extraction
  - Version fingerprinting

- **Phase 1.5: HTTP Security Header Analysis**
  - Real HTTP requests to check headers
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - X-XSS-Protection, Referrer-Policy, Permissions-Policy
  - Header security scoring (0-100)
  - Detailed issue reporting

- **Phase 2: Decision Engine**
  - Service-based Nuclei template selection
  - Intelligent risk scoring
  - Phishing detection (certificate CN mismatch)
  - Weak TLS version detection

- **Phase 3: Nuclei Vulnerability Scan**
  - Targeted template execution
  - Severity filtering
  - Rate limiting support

- **Phase 4: Report Generation**
  - JSON reports with risk scores
  - Multi-format output (XML, TXT, JSON)
  - Comprehensive findings summary

#### NSE Scanner (`nse_scanner.py`)

- **Scan Profiles**
  - quick: Top 100 ports
  - standard: Top 1000 ports
  - full: All 65535 ports
  - security: SSL + Headers + Vulns
  - https: HTTPS security check
  - web: Web application scan

- **Features**
  - Single target and file-based scanning
  - Custom NSE script support
  - Clean output (open ports only)
  - Multiple output formats

### 📋 Documentation

- Comprehensive README.md
- Installation guide
- Usage examples
- API reference
- Troubleshooting guide

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2024-12-16 | Initial release with Nmap + Nuclei pipeline |

---

## Planned Features

- [ ] HTML report generation
- [ ] Email/Slack notifications
- [ ] Database storage (SQLite/PostgreSQL)
- [ ] Web dashboard
- [ ] Scheduled scanning
- [ ] Diff reports between scans
- [ ] Custom template support
- [ ] API mode (REST/GraphQL)

