---
title: Local Privilege Escalation in PowerISO Kernel Driver
slug: 2026-08-poweriso-privilege-escalation
description: PowerISO version 9.3.0.0 contains a vulnerability in the scdemu.sys kernel driver that enables local attackers to perform privilege escalation through improper privilege management.
date: "2026-08-07T03:29:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Power Sofware
products:
  - PowerISO (9.3.0.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation results in improper privilege management.
    confidence_band: high
cves:
  - id: CVE-2026-19189
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19189
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all systems running PowerISO 9.3.0.0
      owner: IT Operations
      due: 24h
      evidence: Affected products list
  mitigation_plan:
    - priority: medium_term
      action: Remove or update PowerISO 9.3.0.0 on vulnerable endpoints
      owner: IT Operations
      addresses: CVE-2026-19189
      evidence: Source reporting of vulnerability in driver
---

A security vulnerability has been identified in PowerISO version 9.3.0.0, specifically within the kernel driver component 'scdemu.sys' located in 'C:\Windows\System32\drivers\'. The flaw stems from improper privilege management, which allows an attacker with existing local access to the system to escalate their privileges to a higher integrity level. This vulnerability is significant because it involves kernel-mode driver code, which historically offers a path for non-privileged users to execute arbitrary code with kernel permissions. Public exploit material is currently available for this vulnerability, increasing the risk of exploitation in targeted attacks. The vendor has not responded to disclosure attempts. Defenders should prioritize auditing the usage of this driver and identifying systems where PowerISO 9.3.0.0 is installed, as there is currently no vendor-provided patch.

## Impact

Successful exploitation of this vulnerability allows a local attacker to bypass standard operating system security controls to gain elevated privileges. This can result in full system compromise, the ability to disable security software, and persistence at the kernel level. As PowerISO is a common utility, organizations running this software are potentially at risk if an attacker gains initial low-privilege access to an endpoint.

## Recommendation

- Identify all endpoints within the environment running PowerISO version 9.3.0.0 using software inventory management tools.
- Implement strict application control policies to restrict unauthorized users from executing code or running utilities in directories where PowerISO resides.
- Monitor for the loading of the 'scdemu.sys' driver in environments where PowerISO is not explicitly required for business operations.
- Evaluate the necessity of the PowerISO software; if not critical, remove the application to eliminate the attack surface provided by the vulnerable driver.
