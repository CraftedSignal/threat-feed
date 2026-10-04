---
title: Remote Code Execution in W CMS via Path Traversal
slug: 2026-10-wcms-rce
description: W CMS versions 3.18.0 and earlier are vulnerable to remote code execution and arbitrary file deletion due to insufficient path validation in the media management API.
date: "2026-10-04T05:00:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vincent-peugnet:w:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - vulnerability
  - path-traversal
vendors:
  - Vincent Peugnet
products:
  - W (<= 3.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: W (wcms) versions 3.18.0 and earlier contain a remote code execution vulnerability due to improper input validation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can upload .php files executed by the web server.
    confidence_band: high
cves:
  - id: CVE-2026-105123
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105123
rules:
  - title: Detect CVE-2026-105123 Exploitation - Path Traversal in Media API
    description: Detects exploitation attempts against CVE-2026-105123 where an attacker uses path traversal sequences to reach outside the media directory
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade W CMS to latest version beyond 3.18.0
      owner: IT Operations
      due: 48h
      evidence: Source states W through 3.18.0 is affected
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version
      owner: IT Operations
      addresses: CVE-2026-105123
      evidence: NVD vulnerability disclosure
---

W CMS (vincent-peugnet/wcms) through version 3.18.0 contains a critical remote code execution vulnerability originating from improper input validation within the API endpoints responsible for media management. Authenticated editors can exploit the path handling logic in the /api/v0/media/upload/[*:path] endpoint to perform path traversal. By utilizing encoded dot-dot-slash (../) sequences, an attacker can bypass directory restrictions to write files, including malicious .php scripts, outside the intended media storage directory. Once placed, these scripts can be executed by the web server. Additionally, the /api/v0/media/[*:path] endpoint is vulnerable to arbitrary file deletion, allowing authenticated users to disrupt the application or remove security configuration files. This vulnerability represents a significant risk to the integrity and availability of the host server environment.

## Attack Chain

1. Attacker authenticates as an editor user within the target W CMS instance.
2. Attacker crafts a malicious HTTP POST request to /api/v0/media/upload/[*:path].
3. The request includes an encoded directory traversal sequence (e.g., %2e%2e%2f) within the path parameter.
4. The application fails to sanitize the path, allowing the attacker to target sensitive web-accessible directories.
5. The attacker uploads a web shell disguised as a .php file to an executable location.
6. The attacker navigates to the location of the uploaded file via the browser to trigger code execution.
7. Optional: The attacker uses the DELETE method on /api/v0/media/[*:path] to remove application logs or critical files for post-exploitation cleanup.

## Impact

Successful exploitation grants an authenticated editor full remote code execution capabilities on the underlying host server. This allows for total system compromise, including the ability to exfiltrate data, modify web content, or pivot into the internal network. Attackers may also cause denial-of-service conditions by deleting arbitrary application files necessary for CMS functionality.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Upgrade W CMS to a version beyond 3.18.0 immediately to remediate CVE-2026-105123.
- Deploy the Sigma rules provided in this brief to detect anomalous API requests targeting the media management endpoints.
- Implement access control reviews for accounts with "editor" permissions, as these are the primary vector for this vulnerability.
- Monitor web server access logs for anomalous POST and DELETE requests to /api/v0/media/ paths containing path traversal characters like "../" or URL-encoded equivalents.
