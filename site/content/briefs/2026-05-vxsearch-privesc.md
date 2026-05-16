---
title: VX Search Unquoted Service Path Privilege Escalation (CVE-2021-47974)
slug: 2026-05-vxsearch-privesc
description: VX Search 13.5.28 is vulnerable to an unquoted service path vulnerability (CVE-2021-47974) in both VX Search Server and VX Search Enterprise services, allowing local attackers to escalate privileges by placing malicious executables in unquoted path directories.
date: "2026-05-16T16:21:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - unquoted service path
  - cve-2021-47974
vendors:
  - Flexense
products:
  - VX Search
  - VX Search Server
  - VX Search Enterprise
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
cves:
  - id: CVE-2021-47974
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47974
  - https://www.exploit-db.com/exploits/50026
  - https://www.vulncheck.com/advisories/vx-search-unquoted-service-path-privilege-escalation
  - https://www.vxsearch.com
rules:
  - title: Detect Unquoted Service Path Exploitation
    description: Detects potential unquoted service path exploitation by monitoring process creation events where an executable runs from a path that is a prefix of a service executable path.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.009
    data_sources:
      - process_creation
      - windows
  - title: Detect Service Execution from Unusual Directory
    description: Detects service execution from unusual directory, indicating possible exploitation attempts related to unquoted service path
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.009
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

VX Search 13.5.28 contains an unquoted service path vulnerability (CVE-2021-47974) affecting both VX Search Server and VX Search Enterprise services. This vulnerability allows a local attacker to escalate privileges to LocalSystem. The vulnerability exists due to the lack of proper quoting around the service executable path, allowing for arbitrary code execution. Successful exploitation requires placing a malicious executable in a directory along the service path. This issue was reported on May 16, 2026. Defenders should ensure the service path is properly quoted or upgrade to a patched version if available.

## Attack Chain

1.  Attacker gains initial local access to the system with a low-privilege account.
2.  The attacker identifies the unquoted service path for VX Search Server or VX Search Enterprise (e.g., C:\Program Files\VX Search).
3.  The attacker creates a malicious executable (e.g., C:\Program.exe).
4.  The attacker places the malicious executable in the first directory in the unquoted service path (e.g., C:\Program Files\VX Search\VXSearchService.exe).
5.  The attacker restarts the VX Search service, either directly or by rebooting the system.
6.  The operating system attempts to execute the service, but due to the unquoted path, it first executes the malicious executable (C:\Program.exe) with LocalSystem privileges.
7.  The malicious executable performs its intended actions, such as creating new administrator accounts or installing malware.
8.  The attacker now has elevated privileges and can perform arbitrary actions on the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to gain complete control of the affected system, due to arbitrary code execution as SYSTEM. This can lead to data theft, system compromise, and potentially lateral movement within the network. Given the nature of VX Search, which is used for file indexing and searching, successful exploitation could also compromise sensitive data stored on the system or network.

## Recommendation

*   Enclose the service path in double quotes to prevent the operating system from misinterpreting the path (reference CVE-2021-47974).
*   Monitor process creation events for executables running from unusual paths, especially those matching the prefix of "C:\Program Files\" using the Sigma rule `Detect Unquoted Service Path Exploitation`.
*   Implement access controls to restrict who can write to directories in the service path.
*   Regularly review and audit service configurations for unquoted paths.
*   Consider using application control solutions to prevent unauthorized executables from running.
