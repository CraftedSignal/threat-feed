---
title: Azure Logic Apps Improper Access Control Vulnerability (CVE-2026-42823)
slug: 2026-05-azure-logic-apps-privilege-escalation
description: CVE-2026-42823 is a critical vulnerability in Azure Logic Apps that allows an authorized attacker to elevate privileges over a network due to improper access control.
date: "2026-05-12T18:42:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - cloud
vendors:
  - Microsoft
products:
  - Azure Logic Apps
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-42823
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42823
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42823
rules:
  - title: Detects CVE-2026-42823 Exploitation Attempt — Suspicious Logic App Action
    description: Detects CVE-2026-42823 exploitation attempt — Monitors for unusual or unauthorized actions within Azure Logic Apps that may indicate privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - azure
  - title: Detects CVE-2026-42823 Exploitation Attempt — Logic App Creation from Unusual Source
    description: Detects CVE-2026-42823 exploitation attempt — Detects Logic App creation events from unusual or unauthorized sources.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

CVE-2026-42823 describes an improper access control vulnerability within Azure Logic Apps. An authorized attacker could exploit this flaw to elevate their privileges within a network. The vulnerability stems from inadequate checks on user permissions, potentially allowing an attacker with limited access to perform actions typically reserved for administrators or higher-level users. This elevation of privilege could grant unauthorized access to sensitive data, allow for the modification of critical system configurations, or enable the attacker to move laterally within the network. This is particularly concerning given the role of Logic Apps in automating and orchestrating workflows across various services.

## Attack Chain

1.  Attacker gains initial authorized access to an Azure account with permissions to use Azure Logic Apps.
2.  Attacker identifies an endpoint or function within Logic Apps that is vulnerable to access control bypass.
3.  Attacker crafts a malicious request to the vulnerable endpoint, exploiting the improper access control mechanism.
4.  The malicious request bypasses the intended access controls, granting the attacker elevated privileges.
5.  Attacker leverages the elevated privileges to access sensitive data within Azure Logic Apps.
6.  Attacker modifies existing Logic Apps workflows to inject malicious code or alter their behavior.
7.  Attacker uses modified workflows to access resources beyond the scope of their initial authorized access, escalating their access across the network.

## Impact

A successful exploitation of CVE-2026-42823 could lead to significant damage, especially in environments heavily reliant on Azure Logic Apps for critical business processes. The vulnerability allows for unauthorized access to sensitive data and critical system configurations. This could result in data breaches, service disruptions, and a compromise of the overall network infrastructure. The CVSS v3.1 base score is 9.9, indicating a critical severity.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-42823 as soon as possible.
*   Review and harden access control policies within Azure Logic Apps to prevent unauthorized privilege escalation.
*   Deploy the provided Sigma rule to detect potential exploitation attempts of CVE-2026-42823 in your environment.
*   Monitor network traffic for suspicious activity related to Azure Logic Apps endpoints.
*   Regularly audit Azure Logic Apps configurations for any signs of unauthorized modifications or access.
