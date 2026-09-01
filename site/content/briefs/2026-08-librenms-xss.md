---
title: Stored XSS via SNMP and Syslog in LibreNMS
slug: 2026-08-librenms-xss
description: LibreNMS is vulnerable to stored cross-site scripting (XSS) due to improper output encoding of SNMP-polled data and syslog messages in legacy PHP templates, allowing attackers to execute arbitrary JavaScript in the browsers of authenticated users.
date: "2026-08-26T20:20:57Z"
lastmod: "2026-09-01T13:06:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:librenms:librenms:*:*:*:*:*:*:*:*
vendors:
  - LibreNMS
products:
  - LibreNMS (< 26.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who controls a monitored network device (via compromised SNMP agent or syslog sender) can inject arbitrary JavaScript that executes when any authenticated LibreNMS user views the affected pages.
    confidence_band: high
cves:
  - id: CVE-2026-84189
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-7w8c-qgxg-m7jx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84189
rules:
  - title: Detect XSS Payload in Web Requests to LibreNMS
    description: Detects potential XSS exploitation attempts against LibreNMS by searching for common JavaScript injection patterns in web server logs, specifically targeting parameters likely to be rendered in health or alert templates.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LibreNMS to 26.5.0 or later
      owner: IT Operations
      due: 48h
      evidence: 'Affected Packages: composer/librenms/librenms (vulnerable: < 26.5.0)'
  hunt_leads:
    - lead: Search web logs for anomalous script-like characters in parameters for health/alerts pages
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Legacy PHP templates echo raw values directly into HTML
updates:
  - at: "2026-09-01T13:06:17Z"
    level: L2
    summary: added CVE-2026-84189; librenms version < 26.5.0
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84189
---

LibreNMS versions prior to 26.5.0 contain multiple stored cross-site scripting (XSS) vulnerabilities within legacy PHP templates located in the `includes/html/` directory. The vulnerability stems from the direct echoing of data retrieved from SNMP-monitored network devices and incoming syslog messages without appropriate output encoding or escaping. 

Specific components impacted include the syslog viewer, alert details page, and device health monitoring dashboards (mempool, storage, and sensors). An attacker with the ability to modify SNMP interface descriptions (ifAlias) or send arbitrary syslog traffic to the LibreNMS server can inject malicious JavaScript. When an authenticated LibreNMS administrator or user views these dashboards, the payload executes within their browser context. This allows attackers to perform actions on behalf of the user, potentially including credential theft or unauthorized configuration changes within the monitoring platform. The issue is exacerbated by the platform's reliance on legacy PHP templates that bypass the auto-escaping features present in newer Blade-based templates.

## Attack Chain

1. Attacker establishes control over a network device or syslog-capable host monitored by the target LibreNMS instance.
2. Attacker modifies the SNMP `ifAlias` (interface description) or sends a crafted syslog `program` string containing a JavaScript payload (e.g., `<img src=x onerror="fetch('...')">`).
3. LibreNMS performs its scheduled SNMP discovery/polling cycle or receives the syslog packet.
4. The unescaped, malicious string is stored directly into the LibreNMS SQL database (e.g., the `ports` table or `syslog` table).
5. An authenticated LibreNMS user navigates to the affected web interface (e.g., Alerts page, Health dashboard, or Syslog view).
6. The legacy PHP template fetches the malicious string from the database and echoes it raw into the HTML response.
7. The victim's web browser renders the HTML and executes the attacker's JavaScript payload within the context of the user session.
8. Attacker achieves unauthorized execution, such as data exfiltration or session manipulation.

## Impact

The vulnerability allows an attacker to compromise the sessions of authenticated users, which can lead to unauthorized access to the network monitoring platform. Given that LibreNMS often holds high-privileged credentials and visibility into sensitive infrastructure, successful exploitation could facilitate lateral movement, information gathering, or operational disruption. The impact is significant for organizations using LibreNMS as a central visibility tool for core network components.

## Recommendation

- Upgrade all LibreNMS installations to version 26.5.0 or later immediately.
- Audit logs for unexpected characters or script tags in SNMP interface descriptions or syslog program fields.
- Restrict access to SNMP configuration and syslog submission channels to trusted IP ranges to prevent unauthorized data injection.
- Use the webserver log source to monitor for unusual POST/GET patterns directed at health, alert, and syslog endpoints.
