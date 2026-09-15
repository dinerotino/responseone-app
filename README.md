# ResponseOne

ResponseOne is a DevSecOps and SOAR demonstration platform that automates security finding collection, storage, analysis, and visualization.

The platform integrates multiple security tools into a centralized workflow and stores findings in PostgreSQL for monitoring through Grafana dashboards.

---

## Features

### Static Application Security Testing (SAST)

- Semgrep

### Dependency Scanning

- Trivy

### Secrets Detection

- Gitleaks

### Dynamic Application Security Testing (DAST)

- OWASP ZAP

### Security Orchestration

- Automated finding ingestion
- Duplicate detection
- Centralized storage

### Monitoring

- PostgreSQL
- Grafana dashboards
- Security metrics

---

## Architecture

GitHub Push
↓
GitHub Actions
↓
Semgrep / Trivy / Gitleaks / ZAP
↓
ResponseOne API
↓
PostgreSQL
↓
Grafana Dashboard

---

## Technology Stack

- Python
- Flask
- PostgreSQL
- Grafana
- GitHub Actions
- Semgrep
- Trivy
- Gitleaks
- OWASP ZAP

---

## API Endpoints

### Health Check

GET /health

### Findings Ingestion

POST /api/findings

Authenticated using:

X-ResponseOne-Token

---

## Security Workflow

1. Developer pushes code.
2. GitHub Actions executes security scans.
3. Findings are generated.
4. Semgrep findings are ingested automatically.
5. Findings are stored in PostgreSQL.
6. Grafana visualizes security metrics.

---

## Future Improvements

- Slack notifications
- Jira integration
- Automated remediation workflows
- Risk scoring engine
- Analyst dashboard

---

## Author

ResponseOne DevSecOps & SOAR Project
