---
title: Untrusted Pointer Dereference in ColorFul iGameCenter
slug: 2026-09-colorful-igamecenter-vuln
description: ColorFul iGameCenter version 1.0.3.4 contains an untrusted pointer dereference vulnerability in the ene.sys driver that can be leveraged by local attackers for privilege escalation.
date: "2026-09-21T20:29:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:colorful:igamecenter:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
vendors:
  - Colorful
products:
  - iGameCenter (1.0.3.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This manipulation causes untrusted pointer dereference.
    confidence_band: high
cves:
  - id: CVE-2026-94403
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94403
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all systems running ColorFul iGameCenter 1.0.3.4
      owner: IT Operations
      due: 24h
      evidence: Source document identifies version 1.0.3.4 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Uninstall ColorFul iGameCenter 1.0.3.4
      owner: IT Operations
      addresses: CVE-2026-94403
      evidence: Vulnerability is present in ene.sys driver; no patch available
---

A security vulnerability has been identified in ColorFul iGameCenter version 1.0.3.4, specifically affecting the IOCTL handler function sub_140001AF0 located within the ene.sys driver. This vulnerability allows an unprivileged local attacker to trigger an untrusted pointer dereference. Because the flaw resides within a kernel-mode driver, successful exploitation could lead to local privilege escalation or complete system instability. Publicly available exploit code currently exists, and the vendor has not provided a patch or response to the disclosure. Defenders should be aware that this requires local access, making it a critical concern for multi-user systems or environments where local user execution is common.

## Attack Chain

1. Attacker gains low-privileged access to the target Windows system.
2. Attacker identifies the loaded ene.sys driver on the system.
3. Attacker crafts a malicious IOCTL request directed at the driver device object.
4. The malicious request reaches the vulnerable sub_140001AF0 function within ene.sys.
5. The function performs an unsafe dereference of an untrusted pointer provided in the IOCTL buffer.
6. Memory corruption occurs, allowing for arbitrary code execution in the kernel context.
7. Attacker achieves local privilege escalation to SYSTEM.

## Impact

The vulnerability poses a high risk to systems running ColorFul iGameCenter, as it allows local unprivileged users to gain kernel-level access. Successful exploitation can result in complete compromise of the host OS, persistence, and bypass of standard user-mode security controls.

## Recommendation

Prioritize monitoring for the existence of the vulnerable driver file on all managed workstations. If the application is not required for business operations, uninstall it immediately to remove the attack surface. Since the vendor has not addressed the issue, consider blocking the loading of the ene.sys driver via WDAC or equivalent kernel-mode code signing policies if the driver is not business-critical.
