---
title: Multiple Vulnerabilities in n8n Allow for Remote Code Execution and Data Manipulation
slug: 2026-05-n8n-multiple-vulns
description: An authenticated, remote attacker can exploit multiple vulnerabilities in n8n to execute arbitrary code, bypass security measures, conduct SQL injection attacks, manipulate data, or disclose sensitive information.
date: "2026-05-13T11:28:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - n8n
  - vulnerability
  - rce
  - sqli
vendors:
  - n8n
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploit System
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1519
rules:
  - title: Detect n8n Security Bypass Attempt
    description: Detects potential security bypass attempts against the n8n web application by looking for abnormal URI patterns.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect n8n SQL Injection
    description: Detects potential SQL injection attempts against the n8n web application based on common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities in n8n, a workflow automation platform, can be exploited by a remote, authenticated attacker. The vulnerabilities permit a range of malicious activities, including arbitrary code execution, bypassing security measures, SQL injection attacks, data manipulation, and sensitive information disclosure. The lack of specific CVE details hinders pinpointing the exact attack vectors, but the broad scope of potential compromise necessitates immediate attention from defenders. Successful exploitation allows an attacker to gain significant control over the n8n instance and potentially pivot to other systems.

## Attack Chain

1. The attacker authenticates to the n8n instance using compromised or brute-forced credentials.
2. The attacker exploits a security bypass vulnerability to circumvent authentication or authorization controls within the n8n application.
3. The attacker leverages an SQL injection vulnerability to execute arbitrary SQL queries against the n8n database, potentially extracting sensitive data or modifying application settings.
4. The attacker exploits a data manipulation vulnerability to alter workflows, inject malicious code into existing workflows, or tamper with stored data.
5. The attacker exploits an arbitrary code execution vulnerability to execute system commands on the n8n server. This could involve uploading a malicious workflow or crafting a specific API request.
6. The attacker establishes persistence by modifying system files or creating new workflows that automatically execute malicious code.
7. The attacker uses the compromised n8n instance as a pivot point to access other systems within the network.
8. The attacker exfiltrates sensitive data obtained from the n8n database or other systems to an external location.

## Impact

Successful exploitation of these vulnerabilities could result in complete compromise of the n8n instance, allowing attackers to execute arbitrary code, manipulate data, and steal sensitive information. Affected organizations could experience data breaches, financial losses, and reputational damage. The absence of specific victim numbers makes quantitative impact assessment challenging.

## Recommendation

*   Deploy the Sigma rule "Detect n8n Security Bypass Attempt" to identify potential security bypass attempts (logsource: webserver).
*   Deploy the Sigma rule "Detect n8n SQL Injection" to identify SQL injection attempts against the n8n instance (logsource: webserver).
*   Thoroughly review n8n logs for suspicious activity, particularly authentication attempts and workflow modifications.
