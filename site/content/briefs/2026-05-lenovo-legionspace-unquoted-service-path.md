---
title: Lenovo LegionSpace 1.7.11.2 Unquoted Service Path Vulnerability
slug: 2026-05-lenovo-legionspace-unquoted-service-path
description: A local exploit has been published for Lenovo LegionSpace 1.7.11.2, detailing an Unquoted Service Path vulnerability in the 'DAService', potentially leading to local privilege escalation.
date: "2026-05-21T13:32:02Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - unquoted-service-path
  - privilege-escalation
  - windows
vendors:
  - Lenovo
products:
  - LegionSpace (1.7.11.2)
affected_os:
  - Windows 11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.exploit-db.com/exploits/52570
rules:
  - title: Detect Unquoted Service Path Exploitation
    description: Detects potential exploitation of unquoted service paths by monitoring for executable creation in the root directory with names that could be misinterpreted as part of a service path.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect DAService Service Creation or Modification
    description: Detects creation or modification of the DAService service with a suspicious binary path.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

A local privilege escalation vulnerability exists in Lenovo LegionSpace version 1.7.11.2 due to an unquoted service path in the 'DAService'. This flaw allows a local attacker to insert arbitrary code into a path within the service's execution path. When the 'DAService' starts, it attempts to execute the program specified in its path. If the path is unquoted and contains spaces, the service may inadvertently execute a malicious program placed in an earlier directory in the path. The exploit, identified as EDB-52570, was published on Exploit-DB on 2026-05-21. Successful exploitation leads to arbitrary code execution with elevated privileges. Lenovo recommends upgrading to version 1.8.12.13 or later to mitigate this vulnerability.

## Attack Chain

1. The attacker identifies an unquoted service path for 'DAService': C:\Program Files\Lenovo\LegionSpace\1.7.11.2\LSDaemon.exe.
2. The attacker creates a malicious executable named "Program.exe" in C:\.
3. The operating system attempts to start the 'DAService'. Due to the unquoted path, the OS parses the path as C:\Program.exe instead of C:\Program Files\Lenovo\LegionSpace\1.7.11.2\LSDaemon.exe.
4. The malicious "Program.exe" is executed.
5. The malicious executable runs with the privileges of the 'DAService', which is LocalSystem.
6. The attacker gains elevated privileges on the system.
7. The attacker can now perform administrative tasks or install malware.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code with elevated privileges. This can lead to a complete compromise of the affected system, including data theft, malware installation, and denial of service. Given the widespread use of Lenovo LegionSpace software, a significant number of systems are potentially vulnerable if not patched.

## Recommendation

*   Upgrade Lenovo LegionSpace to version 1.8.12.13 or later to patch the unquoted service path vulnerability as recommended by the vendor.
*   Deploy the Sigma rule "Detect Unquoted Service Path Exploitation" to identify attempts to exploit this vulnerability by monitoring for the creation of files in the root directory with names matching components of the vulnerable service path.
*   Regularly review service configurations for unquoted paths using the `wmic service get name, pathname, displayname, startmode` command.
