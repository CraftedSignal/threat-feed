---
title: Authenticated Arbitrary File Upload in UnoPim
slug: 2026-09-unopim-rce
description: UnoPim versions prior to 2.1.5 allow authenticated administrators to execute arbitrary code via an insecure TinyMCE image upload endpoint that fails to validate file extensions.
date: "2026-09-02T21:16:04Z"
lastmod: "2026-09-03T19:23:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:unopim:unopim:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - file-upload
  - cve-2026-82524
vendors:
  - UnoPim
products:
  - UnoPim (< 2.1.5)
  - UnoPim (< 2.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can upload a PHP web shell to the public storage disk and execute arbitrary operating system commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Execute arbitrary operating system commands on the server by accessing the uploaded file.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This vulnerability allows an attacker with minimal administrative privileges to bypass authorization checks... and escalate their system permissions.
    confidence_band: high
cves:
  - id: CVE-2026-82524
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82524
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85395
rules:
  - title: Detects CVE-2026-82524 Exploitation - Arbitrary File Upload
    description: Detects potential exploitation of CVE-2026-82524 by identifying POST requests to the TinyMCE upload endpoint containing non-image file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade UnoPim to 2.1.5 or later.
      owner: IT Operations
      due: 48h
      evidence: Source specifies vulnerability in versions before 2.1.5.
  hunt_leads:
    - lead: Search for .php files in public storage directories.
      technique_id: T1505.003
      data_needed:
        - File system logs or integrity monitoring.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker uploads web shell to public storage.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.1.5.
      owner: IT Operations
      addresses: CVE-2026-82524
      evidence: UnoPim version 2.1.5 patch availability.
updates:
  - at: "2026-09-03T19:23:05Z"
    level: L2
    summary: added coverage for UnoPim (< 2.1.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85395
---

UnoPim versions before 2.1.5 are vulnerable to an authenticated arbitrary file upload flaw (CVE-2026-82524). The vulnerability resides in the TinyMCE image upload endpoint, which lacks sufficient validation of file extensions and MIME types. An attacker with administrative privileges can upload a PHP web shell to the application's public storage directory. Once uploaded, the attacker can trigger the malicious script by navigating to the file path returned in the server's HTTP response, resulting in remote code execution (RCE) on the underlying server. This vulnerability is significant because it allows a compromised administrative account to achieve full system control, bypassing intended restrictions on the file upload functionality.

## Attack Chain

1. The attacker authenticates to the UnoPim administrative dashboard using valid or compromised credentials.
2. The attacker navigates to the TinyMCE image upload feature within the application interface.
3. The attacker crafts a request to the TinyMCE image upload endpoint containing a malicious PHP file payload.
4. The UnoPim server receives the file and fails to perform server-side validation of the 'extension' or 'MIME type' attributes.
5. The server stores the malicious PHP file within a public-facing directory on the web server storage disk.
6. The application returns the URL path of the uploaded file to the attacker in an HTTP response.
7. The attacker sends an HTTP GET request to the path of the uploaded PHP file.
8. The web server executes the PHP code, enabling command execution or persistent backdoor access.

## Impact

Successful exploitation allows for full remote code execution on the server hosting the UnoPim instance. As the vulnerability requires administrative access, it is typically used for lateral movement or persistence after an initial account compromise. The impact includes potential full system compromise, data exfiltration from the database or storage, and the ability to pivot to other internal network resources.

## Recommendation

1. Upgrade UnoPim to version 2.1.5 or later immediately to incorporate necessary file validation logic.
2. Monitor web server logs for HTTP POST requests to the TinyMCE image upload endpoint that contain unusual file extensions (e.g., .php, .phtml, .php7).
3. Restrict administrative access to the UnoPim dashboard to known-trusted management IP addresses.
4. Audit the public storage directory for unauthorized script files that do not match expected image file formats.
