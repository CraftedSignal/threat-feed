---
title: Microsoft April 2026 Patch Tuesday Addresses 163 Vulnerabilities
slug: 2026-04-microsoft-patch-tuesday
description: Microsoft's April 2026 Patch Tuesday addresses 163 vulnerabilities, including 8 critical ones, ranging from Tampering to Remote Code Execution and Privilege Escalation, affecting various Microsoft products; it is recommended to apply patches immediately.
date: "2026-04-16T10:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - patch-tuesday
  - vulnerability
  - remote-code-execution
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
cves:
  - id: CVE-2026-33826
    cvss: 8
  - id: CVE-2026-33825
    cvss: 7.8
    epss: 0.03818
  - id: CVE-2026-33824
    cvss: 9.8
  - id: CVE-2026-33827
    cvss: 8.1
  - id: CVE-2026-27913
    cvss: 7.7
  - id: CVE-2026-26151
    cvss: 7.1
references:
  - https://ccb.belgium.be/advisories/warning-microsoft-patch-tuesday-april-2026-patches-163-vulnerabilities-8-critical-154
  - https://msrc.microsoft.com/update-guide/releaseNote/2026-Apr
  - https://thehackernews.com/2026/04/microsoft-issues-patches-for-sharepoint.html
  - https://www.tenable.com/blog/microsofts-april-2026-patch-tuesday-addresses-163-cves-cve-2026-32201
  - https://www.zerodayinitiative.com/blog/2026/4/14/the-april-2026-security-update-review
rules:
  - title: Detect Suspicious RPC Calls to Active Directory
    description: Detects suspicious RPC calls indicative of potential CVE-2026-33826 exploitation in Windows Active Directory environments.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Exploitation Attempts CVE-2026-33824 (Windows IKE Service Extensions)
    description: Detects suspicious network traffic to IKE service extensions, potentially indicating exploitation attempts related to CVE-2026-33824.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Microsoft's April 2026 Patch Tuesday addresses 163 vulnerabilities across its product range, with 8 rated as critical. This update includes fixes for actively exploited zero-day vulnerabilities. The vulnerabilities span multiple categories, including remote code execution (RCE), elevation of privilege, and spoofing. Specifically, CVE-2026-32201 is a zero-day actively exploited in Microsoft SharePoint, and CVE-2026-33826 poses a critical RCE risk in Windows Active Directory environments. Given the wide range of impacted products and the severity of certain vulnerabilities, organizations are strongly advised to prioritize patching to mitigate potential risks of exploitation and lateral movement. The updates cover both server and workstation products.

## Attack Chain

1.  **Initial Access (CVE-2026-32201):** An attacker exploits a spoofing vulnerability in Microsoft SharePoint, potentially through cross-site scripting (XSS).
2.  **Exploitation (CVE-2026-33826):** An authenticated attacker sends a specially crafted RPC call to an RPC host within a restricted Active Directory domain.
3.  **Code Execution (CVE-2026-33826):** The crafted RPC call triggers code execution with the same permissions as the RPC host on the target system.
4.  **Privilege Escalation (CVE-2026-33825):** An attacker leverages insufficient access control granularity in Microsoft Defender to escalate privileges locally.
5.  **Network Propagation (CVE-2026-33824, CVE-2026-33827):** An unauthenticated attacker sends crafted packets to a target with IKE version 2 enabled, or a crafted IPv6 packet to a Windows node where IPSec is enabled, to achieve code execution.
6.  **Defense Evasion (CVE-2026-27913):** An attacker bypasses Secure Boot by exploiting an input validation vulnerability in Windows BitLocker.
7.  **Lateral Movement (CVE-2026-33826):** Threat actors use the foothold established via Active Directory exploitation to move laterally within the organization's network.
8.  **Impact:** The attacker steals data and deploys malware across the compromised network.

## Impact

The successful exploitation of these vulnerabilities could lead to a range of impacts, from data theft and malware deployment to complete system compromise. Given that Microsoft products are widely used across various sectors, a successful attack could affect a large number of organizations, including those in critical infrastructure. The exploitation of Active Directory vulnerabilities (CVE-2026-33826) is particularly concerning, as it could allow attackers to establish a foothold for lateral movement, potentially affecting hundreds or thousands of systems within an enterprise network. The actively exploited SharePoint vulnerability (CVE-2026-32201) could lead to sensitive information disclosure and unauthorized modifications.

## Recommendation

*   Apply the Microsoft April 2026 Patch Tuesday updates immediately to all affected systems, prioritizing those with critical vulnerabilities, especially CVE-2026-32201 (SharePoint) and CVE-2026-33826 (Active Directory).
*   Upscale monitoring and detection capabilities to identify suspicious activity related to the exploitation of these vulnerabilities, as recommended by the advisory.
*   Deploy the Sigma rule to detect suspicious RPC calls indicative of CVE-2026-33826 exploitation in Windows Active Directory environments.
*   Implement firewall rules to mitigate the risk of CVE-2026-33824 exploitation targeting the Windows Internet Key Exchange (IKE) Service Extensions, as suggested in the advisory.
*   Review and enforce strict input validation practices to prevent exploitation of spoofing vulnerabilities like CVE-2026-32201 and CVE-2026-26151.
