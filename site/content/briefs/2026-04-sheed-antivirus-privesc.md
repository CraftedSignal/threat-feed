---
title: Sheed AntiVirus Unquoted Service Path Privilege Escalation (CVE-2016-20061)
slug: 2026-04-sheed-antivirus-privesc
description: Sheed AntiVirus 2.3 contains an unquoted service path vulnerability in the ShavProt service that allows local attackers to escalate privileges by placing a malicious executable in the unquoted path, leading to arbitrary code execution as LocalSystem.
date: "2026-04-04T14:16:18Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - unquoted-service-path
  - cve-2016-20061
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
cves:
  - id: CVE-2016-20061
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20061
  - http://dl.sheedantivirus.ir/setup.exe
  - http://sheedantivirus.ir/
  - https://www.exploit-db.com/exploits/40497
  - https://www.vulncheck.com/advisories/sheed-antivirus-unquoted-service-path-privilege-escalation
iocs:
  - type: url
    value: http://dl.sheedantivirus.ir/setup.exe
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Process Creation in Unquoted Path
    description: Detects process creation events where the executable path contains a space and is not enclosed in quotes, indicating a potential unquoted service path exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect sheed AntiVirus Download
    description: Detects downloads of the sheed AntiVirus setup executable from its official website.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Sheed AntiVirus 2.3 is vulnerable to an unquoted service path vulnerability (CVE-2016-20061) affecting the ShavProt service. This vulnerability, disclosed in April 2026, allows a local attacker with limited privileges to escalate their privileges to SYSTEM. The attack involves placing a malicious executable in a directory within the unquoted service path. When the ShavProt service starts (either through a service restart or system reboot), it attempts to execute binaries along the unquoted path. If the attacker-controlled malicious executable is encountered first, it will be executed with LocalSystem privileges. This poses a significant risk as it allows attackers to gain complete control over the affected system.

## Attack Chain

1.  The attacker identifies the unquoted service path for the ShavProt service in Sheed AntiVirus 2.3. This path is typically found in the Windows Registry under `HKLM\SYSTEM\CurrentControlSet\Services\ShavProt\ImagePath`.
2.  The attacker crafts a malicious executable (e.g., `evil.exe`) designed to perform actions with elevated privileges (e.g., creating a new administrator account or disabling security features).
3.  The attacker places the malicious executable (`evil.exe`) in a directory along the unquoted service path, ensuring it is named to match a directory name within the path. For example, if the path is `C:\Program Files\Sheed AntiVirus\ShavProt.exe`, they might create a directory named "Program" and place `evil.exe` in `C:\evil.exe`. This will make the system attempt to execute `C:\evil.exe Files\Sheed AntiVirus\ShavProt.exe`.
4.  The attacker triggers a restart of the ShavProt service. This can be achieved using the `net stop` and `net start` commands, or through the Services management console (`services.msc`).
5.  Alternatively, the attacker can induce a system reboot to trigger the service to start automatically.
6.  As the service starts, Windows attempts to execute the ShavProt service binary, but due to the unquoted path, it first executes the attacker's malicious executable (`evil.exe`) with LocalSystem privileges.
7.  The malicious executable performs its intended actions, such as creating a new administrator account, modifying system files, or installing backdoors.
8.  The attacker now has persistent access to the system with LocalSystem privileges.

## Impact

Successful exploitation of this vulnerability allows a local attacker to gain complete control over the affected system. This can lead to sensitive data theft, installation of malware, disruption of services, and potential compromise of the entire network if the attacker pivots to other systems. The vulnerability affects all installations of Sheed AntiVirus 2.3, potentially impacting a wide range of users if the antivirus is still deployed.

## Recommendation

*   Apply any available patches or upgrades for Sheed AntiVirus. If no patch is available, consider uninstalling the software.
*   Monitor process creation events for execution of binaries from unusual paths that coincide with unquoted service paths as a generic preventative measure using the "Detect Suspicious Process Creation in Unquoted Path" Sigma rule.
*   Monitor service creation events (if possible via endpoint detection) for services with unquoted paths.
*   Block the download URL `http://dl.sheedantivirus.ir/setup.exe` at the network perimeter.
