---
title: TVicPort64.sys Arbitrary Physical Memory Mapping LPE
slug: 2024-05-tvicport-lpe
description: The TVicPort64.sys driver, signed by EnTech Taiwan in 2006, is vulnerable to arbitrary physical memory mapping, enabling local privilege escalation on Windows systems.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lpe
  - byovd
  - tvicport64.sys
  - privilege-escalation
  - signed-driver
vendors:
  - EnTech Taiwan
products:
  - TVicPort64.sys
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s2747n/add_tvicport64sys_arbitrary_physical_memory/
  - https://github.com/magicsword-io/LOLDrivers/pull/271
rules:
  - title: Detect TVicPort64.sys Driver Load
    description: Detects the loading of the TVicPort64.sys driver, which is known to be vulnerable.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: Detect TVicPort64.sys File Creation
    description: Detects the creation of the TVicPort64.sys file which could be indicative of an attacker attempting to use this vulnerable driver.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The TVicPort64.sys driver, originating from EnTech Taiwan around 2006, is a signed but vulnerable driver that allows for arbitrary physical memory mapping. This vulnerability enables a local user to escalate privileges to SYSTEM by exploiting the driver's ability to directly access and modify physical memory. The driver's age and the fact that it's signed make it a potential candidate for Bring Your Own Vulnerable Driver (BYOVD) attacks. This poses a significant risk to Windows systems as it allows attackers to bypass security measures and gain elevated privileges, potentially leading to complete system compromise.

## Attack Chain

1.  Attacker gains initial access to the target Windows system with standard user privileges.
2.  Attacker drops the vulnerable TVicPort64.sys driver onto the system.
3.  Attacker loads the TVicPort64.sys driver into the kernel, likely exploiting a known method for driver loading, potentially bypassing driver signature enforcement.
4.  The attacker leverages the driver's IOCTLs (Input/Output Control codes) to map arbitrary physical memory into the user-mode address space.
5.  Attacker identifies sensitive kernel data structures or code within the mapped physical memory.
6.  Attacker modifies the identified kernel data structures or code to gain elevated privileges, such as adding the user account to the local Administrators group.
7.  The attacker executes a command or process that requires elevated privileges.
8.  The attacker now operates with SYSTEM-level privileges, allowing them to perform any action on the system, including installing malware, accessing sensitive data, or creating new accounts.

## Impact

Successful exploitation of the TVicPort64.sys vulnerability allows an attacker to achieve local privilege escalation, granting them SYSTEM-level access on the targeted Windows system. This can lead to complete system compromise, allowing the attacker to install malware, steal sensitive data, create new administrative accounts, and perform other malicious activities. The impact is significant, especially in environments where least privilege principles are not strictly enforced.

## Recommendation

*   Monitor for the presence of the TVicPort64.sys driver on systems using file integrity monitoring rules (see file_event log source).
*   Implement driver blocklisting to prevent the TVicPort64.sys driver from being loaded into the kernel.
*   Enable and review Driver Signature Enforcement logs to identify attempts to load unsigned or improperly signed drivers.
*   Deploy the Sigma rule to detect the presence of TVicPort64.sys being loaded as a driver (see process_creation log source).
