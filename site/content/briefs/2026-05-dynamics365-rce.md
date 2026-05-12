---
title: 'CVE-2026-42833: Microsoft Dynamics 365 (on-premises) Remote Code Execution'
slug: 2026-05-dynamics365-rce
description: CVE-2026-42833 is a critical vulnerability in Microsoft Dynamics 365 (on-premises) allowing an authorized attacker with high privileges to execute arbitrary code over the network due to execution with unnecessary privileges.
date: "2026-05-12T18:42:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - remote code execution
  - dynamics 365
vendors:
  - Microsoft
products:
  - Dynamics 365 (on-premises)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-42833
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42833
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42833
rules:
  - title: Detects CVE-2026-42833 Exploitation Attempt — Suspicious Dynamics 365 Process Creation
    description: Detects CVE-2026-42833 exploitation attempt — monitors for suspicious processes spawned by the Dynamics 365 application pool, which could indicate code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-42833 Exploitation Attempt — Dynamics 365 Webshell Creation
    description: Detects CVE-2026-42833 exploitation attempt — monitors for suspicious file creations in the Dynamics 365 directory.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-42833 is a critical vulnerability affecting Microsoft Dynamics 365 (on-premises). The vulnerability stems from a flaw in the software that permits execution with unnecessary privileges, potentially enabling a high-privileged authorized attacker to execute arbitrary code remotely over a network. Successful exploitation of this vulnerability would allow the attacker to perform unauthorized actions, potentially leading to complete system compromise, data theft, or denial of service. This vulnerability poses a significant risk to organizations utilizing the on-premises version of Dynamics 365, requiring immediate patching and mitigation measures.

## Attack Chain

1. An authorized attacker gains high-privileged access to a Dynamics 365 (on-premises) instance. This could be achieved through compromised credentials or an insider threat.
2. The attacker leverages the vulnerability (CVE-2026-42833), exploiting the flaw that allows execution with unnecessary privileges.
3. The attacker crafts a malicious request to trigger the execution of arbitrary code within the Dynamics 365 server environment.
4. The crafted request is sent over the network to the Dynamics 365 server, exploiting a network-accessible component.
5. The Dynamics 365 server processes the request, unintentionally executing the attacker's malicious code due to the privilege escalation vulnerability.
6. The attacker's code executes within the security context of the Dynamics 365 application, potentially gaining elevated privileges.
7. With elevated privileges, the attacker can perform a variety of malicious actions, such as installing malware, exfiltrating sensitive data, or manipulating system configurations.
8. The attacker achieves the objective of remote code execution, leading to full control over the Dynamics 365 server and potential compromise of the entire network.

## Impact

Successful exploitation of CVE-2026-42833 can lead to complete compromise of the Microsoft Dynamics 365 (on-premises) server. An attacker can gain full control over the system, allowing them to steal sensitive data, install malware, disrupt business operations, and potentially pivot to other systems on the network. The vulnerability affects organizations that use the on-premises version of Dynamics 365.

## Recommendation

*   Immediately apply the security update released by Microsoft to address CVE-2026-42833 as detailed in the Microsoft Security Response Center advisory.
*   Monitor network traffic for suspicious activity indicative of exploitation attempts targeting Dynamics 365 servers, using network intrusion detection systems.
*   Deploy the provided Sigma rule to your SIEM and tune it to detect potential exploitation attempts of CVE-2026-42833 based on process creation events.
*   Enforce the principle of least privilege to limit the impact of compromised accounts as it restricts lateral movement and code execution.
*   Review and audit user permissions within Dynamics 365 to ensure that no users have unnecessary elevated privileges, reducing the attack surface.
