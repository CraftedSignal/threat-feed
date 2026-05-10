---
title: Argus Surveillance DVR Unquoted Service Path Vulnerability (CVE-2021-47945)
slug: 2026-05-argus-dvr-unquoted-path
description: Argus Surveillance DVR 4.0 contains an unquoted service path vulnerability in the DVRWatchdog service (CVE-2021-47945), enabling local attackers to escalate privileges by placing a malicious executable in the Program Files directory to be executed as LocalSystem.
date: "2026-05-10T13:21:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - unquoted-service-path
  - privilege-escalation
  - windows
vendors:
  - Argus
products:
  - Surveillance DVR 4.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
cves:
  - id: CVE-2021-47945
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47945
  - https://www.exploit-db.com/exploits/50261
  - https://www.vulncheck.com/advisories/argus-surveillance-dvr-unquoted-service-path-privilege-escalation
rules:
  - title: Detect Suspicious Process Creation in Program Files
    description: Detects a process creation event where an executable is launched from within the Program Files directory by a user who should not be writing there, indicative of a possible unquoted service path exploitation attempt (CVE-2021-47945).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574
      - T1574.009
    data_sources:
      - process_creation
      - windows
  - title: Detect Service Configuration Modification for DVRWatchdog
    description: Detects modifications to the DVRWatchdog service configuration, potentially indicating an attempt to exploit CVE-2021-47945 by changing the service path.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574
      - T1574.009
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Argus Surveillance DVR 4.0 is vulnerable to an unquoted service path vulnerability (CVE-2021-47945) affecting the DVRWatchdog service. This flaw allows a local attacker to achieve privilege escalation on the system. By exploiting the lack of proper quoting in the service's executable path, a malicious actor can insert a rogue executable into a directory along the service's path, typically within the 'Program Files' directory. Upon service restart, the operating system may inadvertently execute the attacker's malicious code instead of the intended legitimate binary, effectively granting the attacker LocalSystem privileges. This vulnerability poses a significant risk to systems where Argus Surveillance DVR 4.0 is installed, as it allows for unauthorized access and control over the affected machine.

## Attack Chain

1.  The attacker gains local access to the target system.
2.  The attacker identifies the unquoted service path vulnerability in the DVRWatchdog service.
3.  The attacker crafts a malicious executable.
4.  The attacker places the malicious executable in a directory that precedes the actual service executable in the unquoted path (e.g., `C:\Program Files\Argus\DVRWatchdog.exe` is vulnerable, attacker places `C:\Program.exe`).
5.  The attacker triggers a restart of the DVRWatchdog service. This can be achieved through various methods, such as using the `services.msc` management console, PowerShell commands, or by restarting the entire system.
6.  The operating system attempts to execute the DVRWatchdog service using the unquoted path. Due to the lack of quotes, the OS misinterprets the path and executes the attacker's malicious executable.
7.  The malicious executable runs with LocalSystem privileges.
8.  The attacker now has elevated privileges and can perform arbitrary actions on the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escalate their privileges to LocalSystem. This grants the attacker complete control over the affected system, enabling them to install software, modify data, create new accounts with full administrative rights, and perform other malicious activities. Given the nature of surveillance DVR systems, attackers may also gain access to sensitive video and audio recordings, potentially leading to privacy breaches and further exploitation.

## Recommendation

*   Apply the vendor-supplied patch or upgrade to a version of Argus Surveillance DVR that addresses CVE-2021-47945 if available.
*   Enclose the service path in quotes to prevent exploitation of the unquoted service path vulnerability. This can be achieved by modifying the service configuration using `sc.exe config "DVRWatchdog" binPath= "\"C:\Program Files\Argus\DVR\DVRWatchdog.exe\""`.
*   Monitor for process creations from unusual locations within the Program Files directory using the Sigma rule `Detect Suspicious Process Creation in Program Files`.
*   Implement strict access control policies to limit the ability of local users to write files to system directories like `Program Files`.
