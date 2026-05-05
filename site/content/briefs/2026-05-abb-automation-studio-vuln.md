---
title: ABB B&R Automation Studio Improper Certificate Validation Vulnerability
slug: 2026-05-abb-automation-studio-vuln
description: ABB B&R Automation Studio versions before 6.5 are vulnerable to improper certificate validation (CVE-2025-11043), potentially allowing an unauthenticated attacker to intercept and interfere with data exchanges, necessitating patching and secure network configurations.
date: "2026-05-05T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - certificate validation
  - man-in-the-middle
vendors:
  - ABB
products:
  - B&R Automation Studio <6.5
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-11043
    cvss: 7.4
    epss: 0.00025
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-125-04
  - https://www.cve.org/CVERecord?id=CVE-2025-11043
rules:
  - title: Detect Potential Man-in-the-Middle Attacks via TLS Certificate Mismatch
    description: Detects discrepancies between expected and presented TLS certificates, indicating potential MITM attacks against B&R Automation Studio.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Redirection for B&R Automation Studio Traffic
    description: Detects potential network redirection attempts for traffic originating from B&R Automation Studio processes.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

ABB B&R Automation Studio versions prior to 6.5 contain an improper certificate validation vulnerability in the OPC-UA client and ANSL over TLS client implementations. This flaw, identified as CVE-2025-11043, could enable an unauthenticated attacker with network access to intercept and manipulate data exchanges between Automation Studio and a server.  The vulnerability was discovered by ABB as part of their internal security analysis. Exploitation could allow an attacker to masquerade as a trusted party. ABB recommends upgrading to version 6.5, which addresses this vulnerability, and operating B&R Automation Studio within Level 2 of the ABB ICS Cyber Security Reference Architecture to mitigate the risk.

## Attack Chain

1.  Attacker gains network access to the targeted system, either through direct connection, misconfigured firewalls, or malware infection.
2.  Attacker intercepts network traffic between the B&R Automation Studio client and the OPC-UA or ANSL over TLS server.
3.  Attacker redirects the communication to a compromised node under their control, manipulating network routing or name resolution.
4.  Attacker generates a maliciously crafted server certificate.
5.  The attacker presents the malicious certificate to the B&R Automation Studio client during the TLS handshake.
6.  Due to the improper certificate validation, the B&R Automation Studio client accepts the malicious certificate.
7.  Attacker intercepts and modifies data exchanged between the client and the legitimate server.
8.  The attacker gains the ability to spoof a trusted server, potentially leading to the disclosure of confidential information or alteration of data in transit.

## Impact

Successful exploitation of CVE-2025-11043 allows an attacker to perform man-in-the-middle attacks, potentially leading to the disclosure of sensitive data or the manipulation of control system processes.  The vulnerability affects ABB B&R Automation Studio users in critical manufacturing and other sectors worldwide. Without proper patching and network segmentation, attackers can gain unauthorized access to ICS communications.

## Recommendation

*   Upgrade to ABB B&R Automation Studio version 6.5, which addresses CVE-2025-11043.
*   Implement network segmentation to minimize network exposure for control system devices, as recommended by CISA.
*   Operate B&R Automation Studio within Level 2 of the ABB ICS Cyber Security Reference Architecture to reduce the risk of successful exploitation.
*   Monitor network traffic for unexpected redirections or connections to untrusted servers using network connection logs.
