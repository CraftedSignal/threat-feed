---
title: Detection of Vulnerable Driver Loading on Windows Systems
slug: 2024-01-vulnerable-driver-load
description: Detection of loading known vulnerable Windows drivers that may indicate persistence or privilege escalation attempts via exploitation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerable-driver
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml
  - https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
  - https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/
  - https://github.com/jbaines-r7/dellicious
  - https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md
  - https://github.com/namazso/physmem_drivers
  - https://github.com/stong/CVE-2020-15368
  - https://github.com/CaledoniaProject/drivers-binaries
  - https://github.com/Chigusa0w0/AsusDriversPrivEscala
  - https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/
  - https://eclypsium.com/2019/11/12/mother-of-all-drivers/
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37969
rules:
  - title: Detect Loading of Known Vulnerable Drivers
    description: Detects loading of known vulnerable drivers using Sysmon Event ID 6.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - image_load
      - windows
  - title: Detect Driver Load by Non-System Processes
    description: Detects when a driver is loaded by a non-system process, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This brief focuses on the detection of vulnerable Windows drivers being loaded into the system, which is a common tactic used by threat actors to achieve persistence and/or escalate privileges. The loading of these drivers can be indicative of ongoing exploitation attempts. This behavior is detected via analysis of Windows Sysmon Event ID 6, which logs driver loading events. Attackers leverage vulnerable drivers to bypass security controls and execute arbitrary code at elevated privilege levels. Successful exploitation can lead to complete system compromise and sensitive data exfiltration. This activity is particularly relevant due to the increasing number of publicly known vulnerable drivers and readily available exploitation techniques. Some drivers are intentionally backdoored, while others have flaws that are exploited.

## Attack Chain

1. An attacker gains initial access to the system through various means, such as exploiting a vulnerability in a user-mode application or through social engineering.
2. The attacker identifies a vulnerable driver present on the system or deploys a malicious vulnerable driver to disk.
3. The attacker leverages a known exploit (e.g., CVE-2022-37969) to load the vulnerable driver into the kernel.
4. Upon successful loading, the vulnerable driver can be used to overwrite critical system data or execute arbitrary code within the kernel context.
5. The attacker utilizes the elevated privileges gained through the vulnerable driver to inject malicious code into other processes or modify system configurations.
6. The attacker establishes persistence by creating new services, modifying registry keys, or planting backdoors within the system.
7. With elevated privileges and persistence established, the attacker can now perform further malicious activities, such as data exfiltration or lateral movement.
8. The attacker achieves their objective, such as deploying ransomware, stealing sensitive data, or disrupting critical systems.

## Impact

Compromise via vulnerable driver exploitation can have severe consequences. Successful exploitation grants attackers SYSTEM level privileges, enabling them to bypass security controls, disable security products, and gain complete control over the compromised system. This can lead to data theft, ransomware deployment, and disruption of critical business operations. There are various vulnerable drivers present in many Windows systems.

## Recommendation

*   Enable Sysmon Event ID 6 to monitor driver loading events on Windows endpoints to enable the rules below.
*   Deploy the Sigma rules provided to detect the loading of known vulnerable drivers (e.g., based on `ImageLoaded` field and cross-referencing with lists of known vulnerable drivers) and tune for your environment.
*   Regularly review and update the list of known vulnerable drivers used in the detection rules to incorporate newly discovered vulnerabilities.
*   Implement driver block rules using Windows Defender Application Control to prevent the loading of known vulnerable drivers.
*   Investigate any alerts generated by these rules promptly to identify and contain potential exploitation attempts.
