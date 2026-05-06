---
title: Windows UPnP Device Host Untrusted Pointer Dereference Vulnerability (CVE-2026-27920)
slug: 2026-04-upnp-privesc
description: CVE-2026-27920 is a local privilege escalation vulnerability in the Windows Universal Plug and Play (UPnP) Device Host due to an untrusted pointer dereference.
date: "2026-04-14T18:17:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - privilege-escalation
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27920
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27920
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27920
rules:
  - title: Suspicious Svchost Child Process Creation
    description: Detects suspicious child processes created by svchost.exe which may indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Device Host Service Executing Suspicious Binary
    description: Detects the Windows UPnP Device Host Service (svchost.exe -k LocalServiceNetworkRestricted) spawning cmd.exe, powershell.exe, or other suspicious binaries.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-27920 is a vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host. This vulnerability stems from an untrusted pointer dereference, which could allow an attacker with local access and authorization to escalate their privileges on the system. The vulnerability was published on April 14, 2026. An attacker who successfully exploits this vulnerability could gain higher-level access to the system potentially leading to complete system compromise. This privilege escalation could be leveraged to install programs, view, change, or delete data, or create new accounts with full user rights.

## Attack Chain

1. An attacker gains initial local access to a Windows system.
2. The attacker identifies that the Windows UPnP Device Host service is running.
3. The attacker crafts a malicious request leveraging the UPnP service.
4. The malicious request triggers the untrusted pointer dereference in the UPnP Device Host.
5. This dereference allows the attacker to overwrite critical system memory.
6. The attacker overwrites memory with a payload designed to inject code into a privileged process.
7. The injected code executes with elevated privileges, such as SYSTEM.
8. The attacker now has the ability to perform actions with elevated permissions.

## Impact

Successful exploitation of CVE-2026-27920 allows a local attacker to elevate their privileges to SYSTEM. This gives the attacker complete control over the affected system. The number of potential victims includes any Windows system with the UPnP Device Host enabled. The impact includes data exfiltration, malware installation, and complete system compromise, which can result in significant financial and reputational damage.

## Recommendation

*   Monitor for suspicious process creations originating from the `svchost.exe` process hosting the UPnP Device Host service to detect potential exploitation attempts.
*   Apply the patch provided by Microsoft for CVE-2026-27920 to remediate the vulnerability.
*   Enable process creation logging to capture command-line arguments for `svchost.exe`, which is required for the provided Sigma rule to function effectively.
