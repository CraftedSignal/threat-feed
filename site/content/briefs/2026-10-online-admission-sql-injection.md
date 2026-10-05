---
title: SQL Injection Vulnerability in Online Admission System Project
slug: 2026-10-online-admission-sql-injection
description: The itsourcecode Online Admission System Project 1.0 contains an unauthenticated SQL injection vulnerability in the login interface, allowing remote attackers to manipulate database queries.
date: "2026-10-05T09:39:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:itsourcecode:online_admission_system_project:*:*:*:*:*:*:*:*
vendors:
  - itsourcecode
products:
  - Online Admission System Project (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105253
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105253
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor /admin/login1.php for SQL injection patterns
      owner: Detection Engineering
      due: 24h
      evidence: NVD report identifies SQL injection in specific URI
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to the /admin directory
      owner: IT Operations
      addresses: CVE-2026-105253
      evidence: Vulnerability allows remote unauthenticated SQLi
---

The Online Admission System Project version 1.0, developed by itsourcecode, contains a critical SQL injection vulnerability. This vulnerability resides within the '/admin/login1.php' script, specifically through improper sanitization of the 'User' argument. An unauthenticated remote attacker can supply malicious input via this parameter to manipulate backend SQL database queries. Successful exploitation could allow an attacker to bypass authentication, extract sensitive information from the database, or potentially gain administrative access to the system. The vulnerability has been publicly disclosed, increasing the risk of exploitation by opportunistic actors. Organizations currently running this software are advised to implement strict input validation or isolate the application until a patch is applied by the vendor.

## Impact

Successful exploitation of this SQL injection vulnerability allows for unauthorized access to the application's database. This could lead to the exposure of student or administrative credentials, exfiltration of personal records stored within the admission system, and potential administrative takeover of the application. Given the nature of the application, the impact primarily concerns the loss of confidentiality and integrity of educational data.

## Recommendation

Prioritize the identification and isolation of all instances of the Online Admission System Project version 1.0 within the environment. Deploy the provided detection rule to monitor for SQL injection attempts against the target login page. If the application is internet-facing, restrict access to the /admin/ directory using a WAF or VPN until the vulnerability is remediated.

## Rules

- title: "Detect SQL Injection Attempt against Online Admission System"
 description: "Detects potential SQL injection attempts targeting the User parameter in /admin/login1.php"
 logsource:
 category: "webserver"
 detection:
 selection:
 cs-uri-stem|endswith: "/admin/login1.php"
 cs-uri-query|contains:
 - "User="
 - "SELECT"
 - "UNION"
 - "--"
 - "OR 1=1"
 condition: selection
 level: "high"
 tags:
 - "attack.initial_access"
 - "attack.t1190"
 tests:
 positive:
 - name: "SQL injection attempt in User parameter"
 data:
 - cs-uri-stem: "/admin/login1.php"
 cs-uri-query: "User=admin' OR 1=1--"
 negative:
 - name: "Legitimate login attempt"
 data:
 - cs-uri-stem: "/admin/login1.php"
 cs-uri-query: "User=testuser"
 falsepositives:
 - "Legitimate users inputting special characters that coincidentally match SQL syntax"
 handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "webserver"
 event_or_channel: "Access Logs"
 required_fields:
 - "cs-uri-stem"
 - "cs-uri-query"
 availability: "available"
 notes: "Requires web server access logs with full query string logging"
 validation:
 status: "needs_environment_validation"
 steps:
 - "Simulate a benign SQL injection string in a lab environment to verify log capture"
 expected_telemetry: "Web server access logs capturing the malicious query string"
 pass_criteria: "Alert fires for the injected test string"
 known_evasions:
 - "Use of URL encoding or obfuscation techniques to bypass keyword-based filters"
 limitations:
 - "Keyword matching may produce false positives on non-malicious user input"
 tuning:
 - source: "Global WAF logs"
 guidance: "Tune based on observed standard usage patterns of the web application"
 suggested_owner: "Detection Engineering"
