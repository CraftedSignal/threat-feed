---
title: Integer Overflow Vulnerability in MSI Dragon Center NTIOLib_X64.sys
slug: 2026-08-msi-dragon-center-integer-overflow
description: A local integer overflow vulnerability in the MmioWritePath function of the MSI Dragon Center driver allows local attackers to escalate privileges via manipulation of argument count or element size parameters.
date: "2026-08-31T21:59:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:msi:dragon_center:*:*:*:*:*:*:*:*
vendors:
  - MSI
products:
  - Dragon Center (<= 2.0.155.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Performing a manipulation of the argument count/elementSize results in integer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-82908
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82908
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all assets running MSI Dragon Center 2.0.155.0 or earlier
      owner: IT Operations
      due: 24h
      evidence: Source defines affected version range up to 2.0.155.0
  mitigation_plan:
    - priority: immediate
      action: Remove or restrict access to MSI Dragon Center on high-value systems
      owner: IT Operations
      addresses: CVE-2026-82908
      evidence: Vulnerability allows local privilege escalation via NTIOLib_X64.sys
---

MSI Dragon Center versions up to and including 2.0.155.0 contain a critical security flaw residing within the NTIOLib_X64.sys kernel-mode driver. Specifically, the MmioWritePath function is susceptible to an integer overflow when processing manipulated input parameters for argument count or element size. Because this component runs with kernel privileges, an attacker with local access to the affected system can exploit this vulnerability to achieve privilege escalation or gain unauthorized control over the operating system. Despite early notification, the vendor has not responded to the disclosure. Proof-of-concept exploit code for this vulnerability has been made public, significantly lowering the barrier for exploitation by local threat actors.

## Impact

The vulnerability carries a CVSS v3.1 base score of 8.8, reflecting the high potential for system-wide compromise. If exploited, a local attacker can bypass standard security controls to execute arbitrary code with kernel-level permissions. This poses a significant threat to systems where MSI Dragon Center is installed, particularly in multi-user environments or systems where limited-privilege users could potentially leverage the driver to escalate their access.

## Recommendation

1. Identify all systems within the environment running MSI Dragon Center version 2.0.155.0 or earlier.
2. Until a patch is provided by the vendor, restrict access to the NTIOLib_X64.sys driver or uninstall MSI Dragon Center on systems where it is not business-critical.
3. Monitor endpoint security logs for unexpected execution of binaries or scripts that interact with kernel-mode drivers, specifically targeting NTIOLib_X64.sys.
4. Implement strict control over local user accounts to prevent unauthorized users from executing code that could interact with vulnerable drivers.
