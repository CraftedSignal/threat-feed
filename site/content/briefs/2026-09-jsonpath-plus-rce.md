---
title: Remote Code Execution in jsonpath-plus via CVE-2025-1302
slug: 2026-09-jsonpath-plus-rce
description: CVE-2025-1302 is a critical remote code execution vulnerability in the jsonpath-plus library, exploitable via malicious JSONPath expressions injected through query parameters.
date: "2026-09-18T18:34:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - injection
  - web-application
  - library-vulnerability
products:
  - jsonpath-plus (v3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability arises from the use of 'eval' within JSONPath filter expressions, allowing an attacker to inject arbitrary code via a crafted JSONPath payload passed through vulnerable query parameters.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Bash'
    evidence: The script attempts through JSONPath payload to trigger remote code execution and establish a reverse shell.
    confidence_band: high
cves:
  - id: CVE-2025-1302
    cvss: 9.8
    epss: 0.10395
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABREWER251-CVE-2025-1302_JSONPATH-PLUS_RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-1302 Exploitation Attempt - JSONPath Injection
    description: Detects exploitation attempts against CVE-2025-1302 by searching for common JSONPath injection payloads designed to execute arbitrary code via the constructor or child_process modules.
    platform: sigma
    severity: critical
    tactics:
      - execution
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
    - Detection Engineering
  immediate_actions:
    - action: Scan inventory for applications importing jsonpath-plus
      owner: IT Operations
      due: 24h
      evidence: Source confirms library-specific vulnerability
  hunt_leads:
    - lead: Search logs for unusual shell execution patterns following inbound HTTP requests
      technique_id: T1059.003
      data_needed:
        - Process creation logs correlated with webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit uses reverse bash shell
  mitigation_plan:
    - priority: immediate
      action: Upgrade jsonpath-plus to 10.3.0 or later
      owner: Development
      addresses: CVE-2025-1302
      evidence: Source identifies library vulnerability
---

CVE-2025-1302 is a critical remote code execution (RCE) vulnerability affecting the jsonpath-plus library. The flaw exists due to the unsafe usage of the 'eval' function within JSONPath filter expressions. An attacker can supply a crafted JSONPath payload through a query parameter (typically mapped to the 'path' field in affected applications), which is then evaluated by the library. This allows for the execution of arbitrary JavaScript commands within the context of the host application. Public proof-of-concept exploits exist, demonstrating the ability to establish reverse shells using 'child_process' primitives in Node.js environments. Organizations using applications that incorporate jsonpath-plus as a dependency for processing user-supplied JSON paths are at high risk of unauthenticated RCE.

## Attack Chain

1. Attacker identifies a web application or API endpoint that accepts user-provided JSONPath expressions as input.
2. Attacker crafts a malicious JSONPath filter expression containing JavaScript code, specifically utilizing the constructor method to reach 'child_process' execution.
3. Attacker sends the payload to the vulnerable endpoint via an HTTP GET or POST request containing the parameter (often named 'path' or 'query').
4. The application processes the input using a vulnerable version of the jsonpath-plus library.
5. The library's filter expression parser triggers an unsafe 'eval' execution of the attacker-supplied JavaScript string.
6. The payload executes commands on the server, such as initiating a reverse shell via '/dev/tcp/' or '/bin/bash'.
7. Attacker establishes a persistent interactive connection back to an attacker-controlled listener for further post-exploitation activities.

## Impact

Successful exploitation results in full remote code execution on the server hosting the affected application. This enables attackers to steal sensitive data, modify application files, pivot into the internal network, or deploy secondary payloads. The vulnerability is rated CVSS 9.8 and requires no privileges or user interaction, making it highly attractive for automated exploitation attempts across internet-facing services.

## Recommendation

Prioritize patching or updating the jsonpath-plus dependency in all custom applications and third-party software to the latest secure version. Until a patch is applied, implement strict input validation to sanitize and reject any JSONPath expressions that contain characters associated with JavaScript execution (e.g., '(', ')', 'eval', 'constructor'). Ensure web application firewalls (WAFs) are configured to detect and block requests containing common JSONPath injection patterns found in the public PoC code, such as those attempting to invoke 'child_process' or 'require'. Monitor web server logs for suspicious requests to API endpoints that contain complex, non-standard JSONPath queries.
