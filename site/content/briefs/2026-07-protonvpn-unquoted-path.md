---
title: ProtonVPN v4.4.1 Unquoted Service Path Vulnerability with Public Exploit
slug: 2026-07-protonvpn-unquoted-path
description: A local privilege escalation vulnerability (Unquoted Service Path) in ProtonVPN v4.4.1 has a public exploit, allowing a local attacker to execute arbitrary code with 'LocalSystem' privileges by placing a malicious executable in a specific directory, which is then launched by the vulnerable 'ProtonVPN Wireguard' service upon startup or restart.
date: "2026-07-07T14:03:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - vulnerability
vendors:
  - Proton Technologies
products:
  - ProtonVPN v4.4.1
affected_os:
  - Windows 10 Pro x64
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: A successful attempt would require the local user to be able to insert their code in the system root path undetected by the OS or other security applications where it could potentially be executed during application startup or reboot. If successful, the local user's code would execute with the elevated privileges of the application.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52624
  - https://protonvpn.com/
rules:
  - title: Detect ProtonVPN Unquoted Service Path Exploitation (CVE-N/A)
    description: Detects attempts to exploit the unquoted service path vulnerability in ProtonVPN v4.4.1 by placing a malicious executable like 'Program.exe' in the root directory, which would be executed with LocalSystem privileges by the vulnerable service.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.008
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A public local privilege escalation exploit has been published on Exploit-DB for ProtonVPN version 4.4.1, leveraging an Unquoted Service Path vulnerability. This flaw specifically affects the 'ProtonVPN Wireguard' service on Windows systems, which is configured to run with `LocalSystem` privileges. The vulnerability arises because the service's executable path, `C:\Program Files (x86)\Proton Technologies\ProtonVPN\ProtonVPN.WireGuardService.exe`, is not enclosed in quotation marks. This allows a local attacker with write access to the root directory or `C:\Program Files (x86)\` to insert a malicious executable named `Program.exe` or `Proton.exe` respectively. Upon the next service start or system reboot, the operating system will incorrectly execute the attacker's binary instead of the legitimate ProtonVPN service, granting the attacker `LocalSystem` privileges. The availability of a working exploit (EDB-52624) significantly elevates the risk for unpatched systems, particularly those tested on Windows 10 Pro x64.

## Attack Chain

1.  A local attacker gains initial access to a vulnerable Windows system with ProtonVPN v4.4.1 installed.
2.  The attacker identifies the 'ProtonVPN Wireguard' service and its unquoted `BINARY_PATH_NAME`: `C:\Program Files (x86)\Proton Technologies\ProtonVPN\ProtonVPN.WireGuardService.exe`.
3.  Leveraging the unquoted path vulnerability, the attacker places a malicious executable named `Program.exe` into the `C:\` directory.
4.  The attacker waits for the system to reboot, or manually triggers a restart of the 'ProtonVPN Wireguard' service.
5.  During service startup, the Windows Service Control Manager attempts to resolve the service's binary path. Due to the unquoted path, it incorrectly executes `C:\Program.exe` instead of the intended ProtonVPN binary.
6.  The malicious `Program.exe` is executed with the privileges of the 'ProtonVPN Wireguard' service, which are `LocalSystem`.
7.  The attacker's arbitrary code gains `LocalSystem` privileges, achieving full system control and local privilege escalation.

## Impact

A successful exploitation of this unquoted service path vulnerability allows a local attacker to escalate their privileges to `LocalSystem`, which is the highest privilege level on a Windows operating system. This grants the attacker complete control over the compromised system, enabling them to install persistent backdoors, deploy additional malware (such as ransomware or infostealers), modify system configurations, create new administrative users, or exfiltrate sensitive data without restriction. Organizations running ProtonVPN v4.4.1 on unpatched Windows endpoints are at risk of lateral movement and full system compromise if an attacker achieves local access.

## Recommendation

*   Immediately update ProtonVPN to the latest secure version to patch the unquoted service path vulnerability. Refer to the vendor's official channels for guidance.
*   Deploy the Sigma rule "Detect ProtonVPN Unquoted Service Path Exploitation (CVE-N/A)" provided in this brief to your SIEM solution to detect attempts to exploit this vulnerability.
*   Ensure Sysmon process creation logging is enabled on all Windows endpoints to ensure the "Detect ProtonVPN Unquoted Service Path Exploitation (CVE-N/A)" rule can collect necessary telemetry.
*   Implement strong access controls and principle of least privilege to restrict write access to the root directory (`C:\`) and `C:\Program Files (x86)\` to prevent malicious binary placement.
