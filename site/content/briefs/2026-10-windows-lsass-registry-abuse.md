---
title: Windows LSASS Credential Theft via Registry Manipulation
slug: 2026-10-windows-lsass-registry-abuse
description: Adversaries manipulate undocumented registry keys under the NTDS service to load malicious DLLs into the Local Security Authority Subsystem Service (LSASS) for credential theft and persistence.
date: "2026-10-12T18:02:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - registry-abuse
  - credential-theft
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The following analytic detects modifications to undocumented registry keys that allow a DLL to load into lsass.exe, potentially capturing credentials.
    confidence_band: high
references:
  - https://blog.xpnsec.com/exploring-mimikatz-part-1/
  - https://github.com/oxfemale/LogonCredentialsSteal/tree/master/lsass_lib
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1547.008/T1547.008.yaml#L5
rules:
  - title: Detect Unauthorized LSASS Driver Registry Modification
    description: Detects modifications to NTDS registry keys used to load malicious DLLs into LSASS, a known credential theft technique (T1547.008).
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.008
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring for NTDS extension points.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry paths for monitoring.
  hunt_leads:
    - lead: Search for existing registry modifications to NTDS keys in the last 30 days.
      technique_id: T1547.008
      data_needed:
        - Endpoint.Registry data model
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This technique is a common persistence mechanism for credential theft.
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrative privileges to prevent unauthorized registry modification.
      owner: IT Operations
      addresses: T1547.008
      evidence: Modification requires administrative or SYSTEM privileges.
---

This threat involves the abuse of undocumented Windows Registry keys, specifically within the NTDS service, to achieve code execution within the context of the Local Security Authority Subsystem Service (LSASS). By modifying the `DirectoryServiceExtPt` or `LsaDbExtPt` keys, an attacker can force the system to load a malicious DLL into the LSASS process. This technique is highly effective for credential theft as it grants the attacker direct access to the memory space where credentials and authentication tokens reside. This method is a known persistence and privilege escalation tactic often utilized by threat actors using post-exploitation toolsets like Mimikatz. Given the critical nature of LSASS, unauthorized modifications to these registry paths should be treated as a significant security incident indicating a high probability of compromise and sensitive data exfiltration.

## Attack Chain

1. Attacker gains initial access to the target Windows system via spearphishing or exploit.
2. Attacker executes a payload with administrative or SYSTEM privileges required to modify the registry.
3. Attacker identifies the target registry keys: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt` or `LsaDbExtPt`.
4. Attacker writes the path of a malicious DLL to the value of the identified registry key.
5. The NTDS service or a system restart triggers the loading of the defined DLL into the `lsass.exe` process.
6. The malicious DLL executes within the LSASS process space.
7. Attacker hooks authentication functions or reads memory to extract credentials (e.g., cleartext passwords, NTLM hashes, Kerberos tickets).
8. Credentials are exfiltrated to the attacker's C2 server for lateral movement.

## Impact

Successful exploitation of this mechanism results in total compromise of credentials cached on the local machine. This exposure allows for rapid lateral movement across the domain, unauthorized access to sensitive accounts, and potential escalation to domain administrator privileges. The impact is critical, as it bypasses traditional security controls by operating within a core Windows service process.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized modifications to the identified registry keys.
* Enable Sysmon Event ID 13 (RegistryValue-Set) across all domain controllers and high-value workstations.
* Monitor for unsigned, non-standard DLL loads into `lsass.exe` using EDR telemetry.
* Investigate any process modifying keys under `\CurrentControlSet\Services\NTDS\` that does not correlate with known administrative software update activity.
