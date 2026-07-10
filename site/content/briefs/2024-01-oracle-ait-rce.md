---
title: CVE-2026-34275 - Oracle Advanced Inbound Telephony Unauthenticated Remote Code Execution
slug: 2024-01-oracle-ait-rce
description: CVE-2026-34275 allows an unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Inbound Telephony versions 12.2.3-12.2.15, potentially leading to a complete takeover of the application.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oracle
  - e-business-suite
  - ait
  - cve-2026-34275
  - rce
vendors:
  - Oracle
products:
  - Oracle Advanced Inbound Telephony
  - Oracle E-Business Suite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34275
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34275
rules:
  - title: Detect Oracle AIT CVE-2026-34275 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-34275 in Oracle Advanced Inbound Telephony via suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Oracle AIT CVE-2026-34275 Suspicious URI Access
    description: Detects potential exploitation attempts of CVE-2026-34275 in Oracle Advanced Inbound Telephony via access to sensitive URIs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-34275 is a critical vulnerability affecting Oracle Advanced Inbound Telephony (AIT) versions 12.2.3 through 12.2.15. This vulnerability, residing within the Setup and Administration component, allows an unauthenticated attacker with network access via HTTP to remotely compromise the Oracle AIT application. Successful exploitation can lead to a complete takeover of the Oracle AIT system, granting the attacker full control over the application and potentially the underlying server. Due to the nature of the affected component, exploitation requires no prior authentication, making it easily exploitable. This poses a significant risk to organizations using vulnerable versions of Oracle E-Business Suite, as it could lead to unauthorized access, data breaches, and disruption of telephony services.

## Attack Chain

1.  Attacker identifies a vulnerable Oracle Advanced Inbound Telephony instance (versions 12.2.3-12.2.15) accessible via HTTP.
2.  Attacker crafts a malicious HTTP request targeting the Setup and Administration component. The specific endpoint and parameters will vary depending on the exact nature of the vulnerability, but no authentication is required.
3.  The malicious HTTP request exploits a flaw in the input validation or processing logic of the Setup and Administration component.
4.  This exploitation allows the attacker to inject arbitrary code into the Oracle AIT application.
5.  The injected code is executed by the Oracle AIT server, granting the attacker initial access.
6.  The attacker leverages this initial access to escalate privileges within the Oracle AIT system.
7.  The attacker uses the elevated privileges to install a persistent backdoor, ensuring continued access even after the initial vulnerability is patched.
8.  The attacker gains full control over the Oracle Advanced Inbound Telephony application, achieving a complete system takeover. This allows the attacker to access sensitive call data, manipulate telephony configurations, and potentially pivot to other systems on the network.

## Impact

Successful exploitation of CVE-2026-34275 can result in a complete takeover of the Oracle Advanced Inbound Telephony system. This could lead to unauthorized access to sensitive call records, modification of telephony configurations, and disruption of critical communication services. The vulnerability allows unauthenticated attackers to compromise the system, potentially impacting all organizations using the affected versions (12.2.3-12.2.15) of Oracle E-Business Suite. The potential for complete system takeover makes this a high-impact vulnerability.

## Recommendation

*   Apply the latest security patches provided by Oracle to address CVE-2026-34275 on all Oracle Advanced Inbound Telephony instances running versions 12.2.3-12.2.15.
*   Implement the provided Sigma rule `Detect Oracle AIT CVE-2026-34275 Exploitation Attempt` to detect potential exploitation attempts in your web server logs.
*   Monitor HTTP traffic to Oracle Advanced Inbound Telephony instances for suspicious activity, particularly requests targeting the Setup and Administration component.
*   Review and restrict network access to Oracle Advanced Inbound Telephony instances to only authorized users and systems.
