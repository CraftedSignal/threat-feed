---
title: Local Privilege Escalation in Kingston FURY CTRL RGB Control Software
slug: 2026-08-kingston-privilege-escalation
description: Kingston FURY CTRL RGB Control Software version 2.0.65.0 contains a vulnerability in the NTIOLib_KSFX.sys driver that allows for local privilege escalation due to improper privilege management.
date: "2026-08-10T01:50:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - driver-vulnerability
vendors:
  - Kingston
products:
  - FURY CTRL RGB Control Software (2.0.65.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The impacted element is an unknown function in the library NTIOLib_KSFX.sys of the component Driver. Performing a manipulation results in improper privilege management.
    confidence_band: high
cves:
  - id: CVE-2026-19381
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19381
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems for Kingston FURY CTRL RGB Control Software 2.0.65.0
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability alert for CVE-2026-19381
  mitigation_plan:
    - priority: immediate
      action: Uninstall Kingston FURY CTRL RGB Control Software 2.0.65.0 on non-essential systems
      owner: IT Operations
      addresses: CVE-2026-19381
      evidence: No vendor patch available
---

A security vulnerability has been identified in Kingston FURY CTRL RGB Control Software version 2.0.65.0. The vulnerability resides within the NTIOLib_KSFX.sys driver component and is classified as an improper privilege management issue. An attacker with local access to the system can leverage this flaw to elevate privileges. Public exploit code for this vulnerability has been released, increasing the risk of exploitation by local threat actors or malware already residing on a host. Despite early notification, the vendor has not provided a patch or a response to the disclosure, leaving systems running this software exposed to potential local privilege escalation (LPE) attacks. This is particularly relevant to defenders as drivers with insecure interfaces frequently serve as vectors for post-exploitation persistence and system-level control.

## Impact

Successful exploitation allows a low-privileged local user to execute code with elevated (system) privileges. This can result in complete system compromise, the disabling of security software, and unauthorized persistence on the affected host. The vulnerability affects systems running the Kingston FURY CTRL RGB Control Software version 2.0.65.0 on the Windows operating system. Given the public availability of the exploit, any endpoint with this software installed is at high risk of lateral movement or privilege escalation if a user account is compromised.

## Recommendation

Prioritize the identification of endpoints running Kingston FURY CTRL RGB Control Software 2.0.65.0. If the software is not business-critical, uninstall it across the fleet to remove the vulnerable driver. For systems where the software must be maintained, implement strict local access controls to minimize the threat of local exploitation. Monitor for the loading of the NTIOLib_KSFX.sys driver on endpoints, especially if loaded by unexpected processes or in unusual paths, and audit local user account activity.
