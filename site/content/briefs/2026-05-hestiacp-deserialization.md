---
title: HestiaCP Deserialization Vulnerability (CVE-2026-43633)
slug: 2026-05-hestiacp-deserialization
description: HestiaCP versions 1.9.0 through 1.9.4 are vulnerable to unauthenticated remote code execution due to a deserialization flaw in the web terminal component (CVE-2026-43633), stemming from a session format mismatch between PHP and Node.js, allowing attackers to inject malicious data via HTTP headers.
date: "2026-05-19T14:17:43Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - deserialization
  - rce
  - cve
vendors:
  - HestiaCP
products:
  - HestiaCP 1.9.0
  - HestiaCP 1.9.1
  - HestiaCP 1.9.2
  - HestiaCP 1.9.3
  - HestiaCP 1.9.4
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-43633
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43633
rules:
  - title: Detect HestiaCP CVE-2026-43633 Attack
    description: Detects CVE-2026-43633 exploitation — Suspicious HTTP headers indicative of deserialization attack attempt in HestiaCP
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect HestiaCP CVE-2026-43633 Post Exploitation - Suspicious Process Execution
    description: Detects CVE-2026-43633 exploitation — Monitors for suspicious process execution after successful exploitation in HestiaCP.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

HestiaCP versions 1.9.0, 1.9.1, 1.9.2, 1.9.3, and 1.9.4 are affected by a critical deserialization vulnerability (CVE-2026-43633) within the web terminal component. This vulnerability arises from an inconsistency in session handling between PHP and Node.js. Specifically, the PHP session handler processes HTTP headers containing crafted data, but the Node.js web terminal component incorrectly deserializes these values, treating them as trusted session data. This discrepancy enables unauthenticated remote attackers to execute arbitrary code at the root level on vulnerable systems where the web terminal feature is enabled. The attacker exploits the session format mismatch to inject malicious commands through HTTP headers, leading to full system compromise.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the HestiaCP server.
2.  The HTTP request includes malicious serialized data within the HTTP headers, targeting session variables used by the web terminal component.
3.  The PHP session handler processes and stores the malicious data in the session.
4.  The Node.js web terminal component deserializes the session data. Due to the format mismatch between PHP's serialization and Node.js's deserialization, the injected malicious data is interpreted as code.
5.  The deserialized code is executed within the context of the Node.js web terminal, granting the attacker control.
6.  The attacker leverages the initial code execution to escalate privileges to root.
7.  With root privileges, the attacker can install malware, create new user accounts, or exfiltrate sensitive data.
8.  The attacker achieves persistent access and control over the compromised HestiaCP server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to gain complete control over the HestiaCP server. This can lead to data breaches, system downtime, and the potential for further attacks on other systems within the network. Given the CVSS v3.1 base score of 10.0, this is a highly critical vulnerability.

## Recommendation

*   Apply available patches or upgrade to a version of HestiaCP beyond 1.9.4 to remediate CVE-2026-43633.
*   Deploy the Sigma rule `Detect HestiaCP CVE-2026-43633 Attack` to identify exploitation attempts based on suspicious HTTP headers in web server logs.
*   Monitor web server logs for unusual patterns in HTTP headers, specifically those related to session management.
*   Disable the web terminal feature if it is not actively used to reduce the attack surface until patches can be applied.
