---
title: Windows UPnP Device Host Use-After-Free Privilege Escalation (CVE-2026-27915)
slug: 2026-04-upnp-privesc
description: A use-after-free vulnerability (CVE-2026-27915) in Windows Universal Plug and Play (UPnP) Device Host allows a locally authorized attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-27915
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27915
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27915
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27915
iocs:
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27915
ioc_counts:
  url: 1
rules:
  - title: UPnP Device Host Suspicious Child Process
    description: Detects suspicious child processes spawned by the UPnP Device Host service, potentially indicating exploitation of CVE-2026-27915.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Device Host Suspicious Network Connection
    description: Detects suspicious network connections initiated by the UPnP Device Host service, potentially indicating exploitation of CVE-2026-27915.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-27915 is a use-after-free vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability allows an attacker who has already gained local access to a Windows system to elevate their privileges. The vulnerability resides within the UPnP service, a component designed to facilitate network device discovery and communication. Successful exploitation could allow a low-privileged user to execute arbitrary code with elevated permissions, potentially gaining full control over the affected system. This vulnerability was published on April 14, 2026, and requires local access, making it particularly dangerous in environments where initial access has been compromised.

## Attack Chain

1. An attacker gains initial local access to a Windows system through social engineering or exploiting a separate vulnerability.
2. The attacker crafts a malicious UPnP service request.
3. The crafted request triggers a use-after-free condition in the UPnP Device Host service (upnphost.exe).
4. The vulnerability allows the attacker to overwrite memory associated with the UPnP Device Host process.
5. The attacker gains the ability to execute arbitrary code within the context of the UPnP Device Host service.
6. Because the UPnP Device Host service runs with elevated privileges, the attacker's code also runs with elevated privileges.
7. The attacker leverages elevated privileges to install malware, modify system settings, or perform other malicious activities.

## Impact

Successful exploitation of CVE-2026-27915 allows an attacker to elevate their privileges from a low-privileged account to SYSTEM, granting them complete control over the compromised machine. This could lead to data theft, malware installation, or further lateral movement within the network. The vulnerability is particularly dangerous in environments where attackers have already gained initial access, as it provides a direct path to privilege escalation.

## Recommendation

*   Monitor process creations by the `upnphost.exe` process for unusual or suspicious child processes to detect potential exploitation attempts. Deploy the Sigma rule provided below to detect this activity.
*   Monitor for unexpected network connections originating from `upnphost.exe`, as exploitation might involve communicating with a C2 server. Consider deploying the Sigma rule provided below and tuning to your environment.
*   Apply the patch provided by Microsoft for CVE-2026-27915 as soon as it becomes available via https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27915.
