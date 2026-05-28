---
title: NetApp Active IQ Unified Manager and OnCommand Insight Remote Code Execution Vulnerability
slug: 2026-05-netapp-rce
description: CVE-2023-22102 describes a vulnerability in NetApp Active IQ Unified Manager and OnCommand Insight that allows a remote attacker to execute arbitrary code.
date: "2026-05-28T11:34:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:oracle:mysql_connector\/j:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*
tags:
  - rce
  - netapp
  - cve-2023-22102
vendors:
  - NetApp
  - Microsoft
  - VMware
products:
  - Active IQ Unified Manager
  - Active IQ Unified Manager for Microsoft Windows
  - Active IQ Unified Manager pour VMware vSphere
  - OnCommand Insight
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569.002
    technique_name: System Services
cves:
  - id: CVE-2023-22102
    cvss: 8.3
    epss: 0.03493
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0656/
  - https://security.netapp.com/advisory/NTAP-20231027-0007
  - https://www.cve.org/CVERecord?id=CVE-2023-22102
rules:
  - title: Detects CVE-2023-22102 Exploitation Attempt - Suspicious URI Access
    description: Detects CVE-2023-22102 exploitation attempt by monitoring for suspicious URI access patterns to NetApp Active IQ Unified Manager or OnCommand Insight.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detects CVE-2023-22102 Exploitation Attempt - Malicious Process Creation
    description: Detects CVE-2023-22102 exploitation attempt by monitoring for the creation of suspicious processes by the Active IQ Unified Manager or OnCommand Insight processes.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A remote code execution vulnerability, tracked as CVE-2023-22102, has been discovered in NetApp Active IQ Unified Manager and OnCommand Insight. This vulnerability impacts Active IQ Unified Manager for Microsoft Windows versions prior to 9.16P2D23, versions prior to 9.18D11 or 9.18P1, Active IQ Unified Manager for VMware vSphere versions prior to 9.16P2D23, versions prior to 9.18D11 or 9.18P1, and OnCommand Insight versions prior to 7.3.15. Successful exploitation of this vulnerability could allow an unauthenticated attacker to execute arbitrary code on the affected system. NetApp has released security bulletin NTAP-20231027-0007 on May 27, 2026, to address this vulnerability.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable NetApp Active IQ Unified Manager or OnCommand Insight instance exposed to the network.
2. The attacker crafts a malicious request, exploiting the CVE-2023-22102 vulnerability.
3. The request is sent to the targeted NetApp server via the network (likely over HTTP/HTTPS).
4. The vulnerable component processes the malicious request, failing to properly sanitize or validate the input.
5. This leads to arbitrary code execution within the context of the application.
6. The attacker gains control over the compromised system.
7. The attacker can then perform further actions such as installing malware, accessing sensitive data, or pivoting to other systems within the network.
8. The final objective is likely data exfiltration, disruption of services, or further lateral movement.

## Impact

Successful exploitation of CVE-2023-22102 can lead to complete compromise of the affected NetApp Active IQ Unified Manager or OnCommand Insight server. This can result in data loss, disruption of management operations, and potential lateral movement to other systems within the network, depending on the permissions and network access of the compromised server. The potential impact ranges from loss of confidentiality and integrity to a complete shutdown of critical services managed by the compromised NetApp product.

## Recommendation

*   Immediately patch all affected NetApp Active IQ Unified Manager and OnCommand Insight instances to the latest versions specified in the NetApp security bulletin NTAP-20231027-0007.
*   Monitor network traffic for suspicious activity targeting NetApp Active IQ Unified Manager and OnCommand Insight servers using the provided Sigma rules.
*   Review and harden network segmentation to limit the blast radius of a potential compromise.
*   Apply the principle of least privilege to the NetApp Active IQ Unified Manager and OnCommand Insight server accounts to restrict the impact of potential code execution.
*   Regularly audit and review the security configuration of NetApp Active IQ Unified Manager and OnCommand Insight instances.
