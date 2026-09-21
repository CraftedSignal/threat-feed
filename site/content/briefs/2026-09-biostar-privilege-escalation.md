---
title: Local Privilege Escalation in BioStar Temperature Monitor Utility
slug: 2026-09-biostar-privilege-escalation
description: CVE-2026-94142 is a local privilege escalation vulnerability in the BioStar Temperature Monitor Utility driver BS_HWMIO64_W10.sys, allowing a local attacker to execute arbitrary code with kernel privileges via a write-what-where vulnerability.
date: "2026-09-21T08:26:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:biostar:temperature_monitor_utility:1.2.1806.2200:*:*:*:*:*:*:*
vendors:
  - BioStar
products:
  - Temperature Monitor Utility (1.2.1806.2200)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Such manipulation of the argument PhysicalAddress leads to write-what-where condition.
    confidence_band: high
cves:
  - id: CVE-2026-94142
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94142
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit endpoints for existence of BS_HWMIO64_W10.sys and version 1.2.1806.2200
      owner: IT Operations
      due: 48h
      evidence: Source identifies this specific driver and version as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the BioStar Temperature Monitor Utility 1.2.1806.2200 from all production hosts
      owner: IT Operations
      addresses: CVE-2026-94142
      evidence: Utility lacks patch and has publicly disclosed exploit code
---

CVE-2026-94142 is a security vulnerability residing in the BioStar Temperature Monitor Utility version 1.2.1806.2200. The vulnerability is located within the IOCTL handler of the BS_HWMIO64_W10.sys driver, specifically in the sub_1105C function. An attacker with local access to the system can exploit improper validation of the PhysicalAddress argument to perform a write-what-where operation. This manipulation allows for kernel memory corruption and potentially leads to the execution of arbitrary code with SYSTEM or kernel-level privileges. Public exploit code for this vulnerability has been disclosed, increasing the risk of exploitation by local attackers seeking to elevate privileges. BioStar did not respond to initial disclosure attempts, and no vendor patch is currently available.

## Impact

Successful exploitation of this vulnerability allows a local user to escalate privileges to the kernel or SYSTEM level. This enables the attacker to bypass operating system security controls, install persistent backdoors, dump sensitive kernel memory, or disable endpoint protection software. The vulnerability affects environments where the BioStar Temperature Monitor Utility is installed on Windows systems.

## Recommendation

Prioritize the identification and removal of vulnerable versions of the BioStar Temperature Monitor Utility (version 1.2.1806.2200) from all endpoints. Monitor system event logs for unusual driver loading activities or unexpected process executions occurring from user-space applications that interact with hardware monitoring interfaces. If the utility is not business-critical, implement a policy to block or uninstall the affected driver BS_HWMIO64_W10.sys.
