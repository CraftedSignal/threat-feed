---
title: Remote Code Execution in Adminer via PDO DSN Injection
slug: 2026-08-adminer-rce
description: Adminer versions prior to 5.4.3 are vulnerable to unauthenticated remote code execution via DSN injection, allowing attackers to write arbitrary PHP files to the web root.
date: "2026-08-25T04:05:07Z"
lastmod: "2026-08-25T04:05:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - rce
  - cve-2026-56705
  - vulnerability
  - web-application
  - cve-2026-34968
vendors:
  - Vrana
products:
  - Adminer
  - Adminer (< 5.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Adminer before 5.4.3 fails to sanitize the server field... allowing unauthenticated attackers to inject ODBC parameters.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can inject TraceFile and TraceOn parameters to write PHP code to the web root, achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-56705
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56705
  - https://github.com/vrana/adminer/security/advisories/GHSA-r4x9-5m63-3vxw
  - https://www.vulncheck.com/advisories/adminer-before-remote-code-execution-via-mssql-pdo-dsn-injection
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34968
  - https://github.com/vrana/adminer/security/advisories/GHSA-6pg3-chwq-wgqc
  - https://www.vulncheck.com/advisories/adminer-before-arbitrary-file-deletion-via-sqlite-drop
rules:
  - title: Detect CVE-2026-56705 Exploitation - Adminer DSN Injection
    description: Detects exploitation attempts against Adminer by searching for semicolon-injected DSN parameters in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-34968 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-34968 by searching for path traversal sequences in the db[] parameter during Adminer database drop operations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Adminer to version 5.4.3
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-56705 remediation requires patching to 5.4.3.
  hunt_leads:
    - lead: Search web logs for semicolon or 'TraceFile' substrings in requests to Adminer.
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves injecting ODBC parameters via semicolons.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Adminer interface via firewall or IP whitelisting.
      owner: IT Operations
      addresses: CVE-2026-56705
      evidence: Unauthenticated remote access is required for exploitation.
updates:
  - at: "2026-08-25T04:05:42Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-34968 Exploitation Attempt'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-34968
---

Adminer versions prior to 5.4.3 contain a critical vulnerability (CVE-2026-56705) due to the failure to properly sanitize the server field during the construction of a PHP Data Objects (PDO) Data Source Name (DSN) string. This flaw enables unauthenticated remote attackers to perform DSN injection by providing malicious input containing semicolons. By injecting specific ODBC parameters, such as 'TraceFile' and 'TraceOn', an attacker can force the application to write arbitrary content to a file on the server. If this file is placed within the web root, the attacker can execute the written PHP code, leading to full system compromise. This vulnerability represents a high-risk vector for organizations running instances of Adminer exposed to the internet.

## Attack Chain

1. Attacker identifies a target running a vulnerable version of Adminer (prior to 5.4.3) via banner grabbing or service discovery.
2. Attacker interacts with the Adminer login interface, targeting the server field input.
3. Attacker submits a crafted request containing a semicolon-delimited DSN string designed to inject ODBC configuration parameters.
4. The vulnerable PHP code processes the input and initializes a PDO connection using the malicious DSN string.
5. The underlying database driver (specifically MS SQL PDO) processes the injected 'TraceFile' and 'TraceOn' parameters.
6. The application writes the trace output, which includes the injected PHP payload, to a file in the web root.
7. The attacker sends an HTTP request to the newly created file, triggering the web server to execute the injected PHP code.
8. Successful execution of the payload provides the attacker with remote code execution (RCE) on the server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to achieve arbitrary remote code execution on the server hosting Adminer. This can lead to total system compromise, data exfiltration, lateral movement within the network, and the deployment of persistent malware or backdoors. Organizations across any sector using Adminer to manage database instances are susceptible to this risk if they are running version 5.4.3 or earlier.

## Recommendation

* Update Adminer to version 5.4.3 or later immediately to mitigate CVE-2026-56705.
* Inspect web server logs for requests containing semicolons or common ODBC parameters like 'TraceFile' directed at the Adminer login endpoint.
* Implement access controls or network segmentation to restrict access to the Adminer interface to authorized personnel only.
* Deploy the Sigma rule below to monitor for exploitation attempts against the Adminer service.
