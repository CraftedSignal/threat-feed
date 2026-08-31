---
title: C-MOR Video Surveillance Directory Traversal Vulnerability
slug: 2026-08-c-mor-traversal
description: C-MOR Video Surveillance versions up to 6.0104 are vulnerable to an unauthenticated directory traversal attack in the show-movies.pml component, allowing remote attackers to read arbitrary files.
date: "2026-08-31T14:04:31Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - webapps
  - directory-traversal
  - cve-2026-51134
  - surveillance
vendors:
  - za-internet GmbH
products:
  - C-MOR Video Surveillance (<= 6.0104)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The directory traversal vulnerability allows access to arbitrary system files via specially crafted HTTP requests.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52666
rules:
  - title: Detects CVE-2026-51134 Exploitation - Directory Traversal in C-MOR
    description: Detects attempts to exploit CVE-2026-51134 by identifying directory traversal sequences in the 'cam' parameter of requests to show-movies.pml.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to identify exploitation attempts against C-MOR systems.
      owner: Detection Engineering
      due: 24h
      evidence: Exploit availability increases the risk of active exploitation.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the C-MOR video surveillance interface.
      owner: IT Operations
      addresses: CVE-2026-51134
      evidence: The vulnerability allows unauthenticated access; network segregation reduces exposure.
---

C-MOR Video Surveillance (versions <= 6.0104) by za-internet GmbH contains a directory traversal vulnerability that allows unauthenticated remote attackers to read arbitrary files from the underlying system. The vulnerability exists within the show-movies.pml component, which fails to properly sanitize the 'cam' input parameter. By supplying specially crafted HTTP requests containing traversal sequences (e.g., '../'), an attacker can escape the intended web application directory and access sensitive system files. This vulnerability, tracked as CVE-2026-51134, is documented with a public proof-of-concept exploit. Given the nature of video surveillance systems, unauthorized access to system files could lead to the exposure of credentials, configuration data, or other sensitive information, facilitating further system compromise.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing C-MOR Video Surveillance instances.
2. Attacker crafts a malicious HTTP GET request targeting the 'show-movies.pml' endpoint.
3. Attacker injects directory traversal sequences (../) into the 'cam' parameter within the URL query string.
4. The vulnerable web application processes the request without sanitizing the input path.
5. The server-side code resolves the path relative to the root directory or unintended application directories.
6. The application returns the contents of the requested file (e.g., /etc/passwd) in the HTTP response body.
7. Attacker parses the response to exfiltrate system configuration or sensitive data.

## Impact

Successful exploitation allows unauthenticated remote attackers to retrieve arbitrary files from the filesystem of the C-MOR surveillance server. This can lead to the exposure of sensitive configuration files, system credentials, or other internal application data. The scope of impact is limited to the server running the vulnerable software, but potentially provides attackers with sufficient information to elevate privileges or pivot further into the internal network.

## Recommendation

1. Patch C-MOR Video Surveillance to the latest version immediately if a fix is provided by za-internet GmbH; if no patch is available, restrict access to the web interface via network controls.
2. Deploy the provided Sigma rule to detect attempts to access sensitive system files via the show-movies.pml component.
3. Monitor web server access logs for anomalous requests containing directory traversal sequences (e.g., ../) directed at the show-movies.pml script.
