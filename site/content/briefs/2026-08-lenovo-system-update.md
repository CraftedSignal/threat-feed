---
title: Authentication Bypass in Lenovo System Update
slug: 2026-08-lenovo-system-update
description: CVE-2026-6387 is an authentication bypass vulnerability in Lenovo System Update (versions prior to 5.08.04.85) that allows a local authenticated user to escalate privileges and execute arbitrary code.
date: "2026-08-13T15:39:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Lenovo
products:
  - System Update
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A potential authentication bypass vulnerability was reported in Lenovo System Update that could allow a local authenticated user to execute arbitrary code with elevated privileges.
    confidence_band: high
cves:
  - id: CVE-2026-6387
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6387
  - https://support.lenovo.com/us/en/product_security/LEN-213316
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Lenovo endpoints to identify versions of System Update older than 5.08.04.85.
      owner: IT Operations
      due: 48h
      evidence: Lenovo security advisory LEN-213316
  mitigation_plan:
    - priority: immediate
      action: Patch Lenovo System Update to version 5.08.04.85 or newer.
      owner: IT Operations
      addresses: CVE-2026-6387
      evidence: NVD vulnerability details
---

Lenovo has identified a security vulnerability, CVE-2026-6387, within the Lenovo System Update software, which is widely deployed across Lenovo workstations and laptops. This flaw is categorized as CWE-290 (Authentication Bypass by Spoofing) and exists due to improper authentication handling within the application. A local authenticated user can exploit this vulnerability to bypass existing security controls, facilitating privilege escalation to execute arbitrary code with elevated permissions on the host system. This vulnerability affects all versions of Lenovo System Update prior to 5.08.04.85 on the Windows platform. Given that Lenovo System Update typically runs with system-level privileges to perform driver and firmware maintenance, successful exploitation grants an attacker full control over the affected endpoint.

## Impact

Successful exploitation allows a local user, who may have restricted or low-level access, to achieve arbitrary code execution at elevated privilege levels. This poses a significant risk to organizational endpoints by potentially enabling attackers to persist, disable security software, or exfiltrate sensitive data from the local machine. All organizations utilizing Lenovo hardware with affected versions of System Update are at risk of local privilege escalation.

## Recommendation

- Identify all workstations and servers within the environment currently running Lenovo System Update versions older than 5.08.04.85.
- Prioritize the deployment of the update to version 5.08.04.85 or later across the fleet via Lenovo's official update channels or enterprise management tools.
- Monitor local process creation logs for unexpected or unauthorized child processes spawned by 'SUService.exe' or other Lenovo System Update associated binaries, which may indicate attempted exploitation.
- Validate that the remediation (version 5.08.04.85) is applied to all systems identified in the vulnerability scan.
