---
title: CVE-2026-33823 Microsoft Teams Information Disclosure Vulnerability
slug: 2024-01-22-teams-infoleak
description: CVE-2026-33823 is an information disclosure vulnerability in Microsoft Teams that allows an authorized attacker to disclose sensitive information over a network due to improper authorization.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - cloud
  - microsoft-teams
vendors:
  - Microsoft
products:
  - Teams
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33823
rules:
  - title: Detect CVE-2026-33823 Exploitation — Suspicious Teams Events Request
    description: Detects CVE-2026-33823 exploitation — Network requests to Microsoft Teams events portal with suspicious parameters indicating potential information disclosure.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

CVE-2026-33823 is an information disclosure vulnerability affecting Microsoft Teams. This flaw stems from improper authorization controls within the Teams Events Portal. An attacker who already possesses some level of authorized access to a Teams environment can exploit this vulnerability to potentially gain unauthorized access to sensitive information traversing the network. The vulnerability highlights the importance of rigorous authorization checks in cloud-based collaboration platforms to prevent lateral information access and maintain data confidentiality. Defenders should prioritize patching and investigate any anomalous data access patterns within their Teams deployments.

## Attack Chain

1.  Attacker gains initial authorized access to a Microsoft Teams environment (e.g., as a guest user or standard employee).
2.  Attacker identifies the vulnerable Teams Events Portal component lacking proper authorization checks.
3.  Attacker crafts a malicious network request targeting the vulnerable endpoint within the Teams infrastructure.
4.  The request bypasses the insufficient authorization controls due to the existing authenticated session.
5.  The vulnerable component processes the request, inadvertently disclosing sensitive data.
6.  The data is transmitted back to the attacker over the network.
7.  Attacker analyzes the disclosed information, potentially revealing internal configurations, user data, or other confidential details.

## Impact

Successful exploitation of CVE-2026-33823 allows an authorized attacker to disclose sensitive information over a network, potentially leading to unauthorized access to user data, internal configurations, or other confidential details within a Microsoft Teams environment. The severity of the impact depends on the type and volume of information disclosed.

## Recommendation

*   Apply the Microsoft patch for CVE-2026-33823 immediately to remediate the improper authorization vulnerability in Microsoft Teams.
*   Deploy the Sigma rule `Detect CVE-2026-33823 Exploitation — Suspicious Teams Events Request` to identify potential exploitation attempts by monitoring network traffic.
