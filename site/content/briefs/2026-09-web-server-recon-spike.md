---
title: Detection of Web Server Reconnaissance via Error Log Spikes
slug: 2026-09-web-server-recon-spike
description: This brief covers the detection of automated reconnaissance activities, such as vulnerability scanning and fuzzing, which manifest as significant spikes in web server error logs.
date: "2026-09-18T19:24:37Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - reconnaissance
  - web-security
  - log-analysis
vendors:
  - Apache
  - Microsoft
  - Nginx
products:
  - HTTP Server
  - Tomcat
  - IIS
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This rule detects unusual spikes in error logs from web servers, which may indicate reconnaissance activities such as vulnerability scanning or fuzzing attempts by adversaries.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: These activities often generate a high volume of error responses as they probe for weaknesses in web applications.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595.003
    technique_name: Wordlist Scanning
    evidence: A typical pattern is an automated scanner sweeping endpoints like /admin/, /debug/, /.env, /.git, and backup archives while mutating query parameters.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/reconnaissance_web_server_unusual_spike_in_error_logs.toml
  - https://attack.mitre.org/techniques/T1595/
  - https://attack.mitre.org/techniques/T1595/002/
  - https://attack.mitre.org/techniques/T1595/003/
rules:
  - title: Potential Spike in Web Server Error Logs
    description: Detects an unusual volume of error responses (4xx/5xx) from a single source IP, indicating potential reconnaissance activity such as scanning or fuzzing.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
      - T1595.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule and monitor for high-volume false positives
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Analyze top requested paths by IPs flagged for high error counts
      technique_id: T1595
      data_needed:
        - Web access logs with requested URI paths
      priority: medium
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: medium_term
      action: Enable per-IP rate limiting at the WAF or CDN level for 404/403/500 patterns
      owner: IT Operations
      addresses: T1595
---

Adversaries often perform automated reconnaissance against public-facing web infrastructure to identify weaknesses. This activity frequently involves large-scale scanning or fuzzing attempts targeting sensitive paths such as /admin/, /debug/, /.env, /.git, and various backup archives. Because these probes often target non-existent resources or unauthorized directories, they generate a high volume of HTTP 403 (Forbidden) and 404 (Not Found) error responses. In some cases, the probes may trigger backend application errors resulting in HTTP 5xx responses. Detecting a sudden spike in these error logs from a single source IP provides an early-warning signal that an entity is actively probing an organization's attack surface. While this activity is often automated, it is a precursor to potential exploitation attempts and requires differentiation from legitimate internal QA testing or transient infrastructure failures.

## Impact

Successful reconnaissance allows adversaries to map internal application structures, identify exposed configuration files, locate backup files, or uncover unpatched administrative consoles. If left unmonitored, these scan patterns often precede targeted exploitation of identified vulnerabilities, potentially leading to unauthorized access, sensitive data exfiltration, or secondary system compromise.

## Recommendation

- Implement the provided detection logic to monitor web server error logs (Nginx, Apache, Tomcat, IIS) for spikes in volume from single source IPs.
- Enrich identified noisy source IPs with geolocation, ASN, and threat intelligence feeds to differentiate between known scanners and authorized testing infrastructure.
- Configure WAF or load balancer rate-limiting rules to automatically throttle or block IPs generating excessive 403/404/500 errors within short time windows.
- Ensure logging configurations capture the true client IP (via X-Forwarded-For or True-Client-IP headers) to prevent misidentification of legitimate traffic behind NAT or load balancers.
- Review and harden web server configurations to disable directory listings, restrict access to sensitive files (.env, .git), and reject unused HTTP methods (e.g., TRACE, OPTIONS).
