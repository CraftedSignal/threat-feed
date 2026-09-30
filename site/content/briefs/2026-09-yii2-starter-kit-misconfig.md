---
title: Unauthenticated Exposure of Yii Debug and Gii Modules in yii2-starter-kit
slug: 2026-09-yii2-starter-kit-misconfig
description: Versions of yii2-starter-kit up to 4.2.0 are vulnerable to unauthorized access due to insecure default configurations allowing remote attackers to access debugging and code generation modules.
date: "2026-09-30T18:35:59Z"
lastmod: "2026-09-30T18:36:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:yii2-starter-kit:yii2-starter-kit:*:*:*:*:*:*:*:*
tags:
  - web-application
  - misconfiguration
  - rce
  - information-disclosure
  - file-upload
  - vulnerability
vendors:
  - yii2-starter-kit
products:
  - yii2-starter-kit (<= 4.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can access the debug endpoint to read sensitive data... or access the Gii endpoint to generate and write PHP files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: access the Gii endpoint to generate and write PHP files into the application directory
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers with manager role can upload PHP scripts to the web-accessible storage directory and request them to execute arbitrary code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-103475
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103475
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103474
rules:
  - title: Detect Exploitation Attempts against Yii Debug and Gii Modules
    description: Detects unauthorized access to Yii framework debugging and code generation endpoints which are exposed in vulnerable yii2-starter-kit configurations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-103474 Exploitation - PHP File Upload to Web Storage
    description: Detects potential exploitation of CVE-2026-103474 by identifying POST requests to backend storage upload paths that contain PHP file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan internal web application inventory for yii2-starter-kit installations
      owner: SOC
      due: 24h
      evidence: CVE-2026-103475 vulnerability in yii2-starter-kit
  mitigation_plan:
    - priority: immediate
      action: Disable debug and Gii modules or restrict access by IP in application config
      owner: IT Operations
      addresses: CVE-2026-103475
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-30T18:36:38Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-103474 Exploitation - PHP File Upload to Web Storage'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103474
---

yii2-starter-kit versions through 4.2.0 contain a critical configuration vulnerability (CVE-2026-103475) that leaves the Yii debug and Gii modules exposed to all IP addresses. By default, the application sets the 'allowedIPs' parameter to ['*'], enabling unauthenticated remote access to these administrative endpoints.

The debug module allows unauthorized users to view sensitive application internals, including session cookies, environment variables, and database query logs, facilitating further attacks or account takeovers. The Gii module is a code generation tool that allows users to create and write PHP files directly into the application directory. Attackers can leverage this functionality to perform remote code execution by injecting and executing arbitrary PHP code. Because these endpoints are often exposed without requiring authentication in this misconfigured state, an attacker needs only network reachability to the web application to achieve full system compromise.

## Attack Chain

1. Attacker performs reconnaissance to identify applications running yii2-starter-kit by fingerprinting web headers or file paths.
2. Attacker probes for the presence of the Yii debug module via common paths such as /debug/default/index.
3. Attacker accesses the exposed debug endpoint to harvest sensitive data, including session cookies and database credentials found in logs.
4. Attacker navigates to the Gii module endpoint, typically located at /gii.
5. Attacker utilizes Gii code generation features to create a new controller or model containing arbitrary PHP malicious payloads.
6. Attacker triggers the writing of the crafted PHP file into the application's source directory.
7. Attacker navigates to the newly created file URL to trigger code execution.
8. Final objective achieved: remote command execution leading to full application control or data exfiltration.

## Impact

Successful exploitation allows unauthenticated remote attackers to obtain sensitive information, including session identifiers and database contents, or achieve remote code execution by injecting arbitrary PHP files into the application directory. This affects all deployments of yii2-starter-kit versions 4.2.0 and earlier using the default development configuration, potentially impacting any organization running this starter kit in a production environment.

## Recommendation

1. Immediately audit all instances of yii2-starter-kit to identify if the development configuration is active in production.
2. Restrict access to /debug and /gii endpoints via web server configuration (e.g., Nginx/Apache) or by updating the application configuration to limit 'allowedIPs' to trusted internal addresses.
3. Update yii2-starter-kit to a version that enforces secure default configurations, or explicitly disable the debug and Gii modules in production environments.
4. Review web server logs for HTTP requests directed at /debug/* or /gii/* paths originating from unauthorized external IP addresses.
