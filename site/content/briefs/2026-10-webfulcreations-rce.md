---
brief_id: brief-2026-10-30-webfulcreations-rce
event_id: brief-2026-10-30-webfulcreations-rce
revision: 1
activity_at: "2026-10-30T04:29:55Z"
title: 'Webfulcreations Computer Repair Shop: Unauthenticated remote code execution (CVE-2024-51793)'
slug: 2026-10-webfulcreations-rce
description: CVE-2024-51793 is a critical unauthenticated arbitrary file upload vulnerability in the Webfulcreations Computer Repair Shop WordPress plugin, allowing attackers to achieve remote code execution via the admin-ajax.php endpoint.
date: "2026-10-30T04:29:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source information regarding CVE-2024-51793 is sufficient for detection development.
cpes:
  - cpe:2.3:a:webfulcreations:computer_repair_shop:*:*:*:*:*:wordpress:*:*
vendors:
  - Webfulcreations
products:
  - Computer Repair Shop (<= 3.8115)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated arbitrary file upload in WordPress plugin admin-ajax.php enabling 0-click RCE.
    confidence_band: high
cves:
  - id: CVE-2024-51793
    cvss: 10
    epss: 0.01845
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOSHUAPROVOSTE-0-CLICK-RCE-EXPLOIT-FOR-CVE-2024-51793
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOSHUAPROVOSTE-0-CLICK-RCE-EXPLOIT-FOR-CVE-2024-51793&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2024-51793 Exploitation - Unauthenticated File Upload
    description: Detects potential exploitation attempts of CVE-2024-51793 by monitoring for suspicious POST requests to admin-ajax.php often used in file upload attacks.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Computer Repair Shop to a version above 3.8115.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is exploitable in versions <= 3.8115.
  hunt_leads:
    - lead: Search for newly created .php files in the web server directory structure, particularly within wp-content/uploads.
      technique_id: T1505.003
      data_needed:
        - File system audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit script drops PHP payload to facilitate RCE.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block suspicious POST requests to admin-ajax.php.
      owner: SOC
      addresses: CVE-2024-51793
      evidence: Exploitation relies on unauthenticated POST requests to the admin-ajax.php endpoint.
---

CVE-2024-51793 is an unauthenticated arbitrary file upload vulnerability in the Webfulcreations Computer Repair Shop WordPress plugin (versions 3.8115 and below). The flaw resides in the handling of requests to `admin-ajax.php`, which can be leveraged to upload arbitrary PHP files without authentication. Once uploaded, these files can be executed, leading to full system compromise. Proof-of-concept exploit code is publicly available.

## Attack Chain
1. Attacker identifies a target running a vulnerable version of the Computer Repair Shop plugin.
2. Attacker sends an unauthenticated POST request to the `admin-ajax.php` endpoint.
3. The request exploits the vulnerability to bypass file type validation.
4. A malicious PHP payload is uploaded to the web server directory.
5. The server response provides the direct URL to the newly uploaded file.
6. Attacker accesses the PHP file via a browser to execute code and obtain an interactive shell.

## Impact
Successful exploitation allows for unauthenticated remote code execution with the privileges of the web server process. This results in complete compromise of confidentiality, integrity, and availability (CVSS 10.0).

## Recommendation
- Update Webfulcreations Computer Repair Shop to a version beyond 3.8115 immediately.
- Implement monitoring for unexpected file creation within the WordPress `wp-content/uploads` directory or other web-accessible paths.
- Inspect web server access logs for anomalous POST requests directed at `admin-ajax.php` containing file upload parameters.
- If patching is not immediately feasible, restrict access to `admin-ajax.php` for unauthorized users via firewall or web application firewall (WAF) rules.
