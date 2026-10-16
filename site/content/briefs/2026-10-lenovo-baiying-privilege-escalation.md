---
title: Improper Authorization in Lenovo Baiying PC Client
slug: 2026-10-lenovo-baiying-privilege-escalation
description: A local improper authorization vulnerability in Lenovo Baiying PC Client allows an authenticated user to achieve privilege escalation through arbitrary code execution.
date: "2026-10-16T00:41:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lenovo:baiying_pc_client:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - local-exploitation
vendors:
  - Lenovo
products:
  - Baiying PC Client
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability could allow a local authenticated user to execute arbitrary code with elevated privileges.
    confidence_band: high
cves:
  - id: CVE-2026-92629
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92629
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all assets running Lenovo Baiying PC Client to assess exposure scope.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92629 advisory
  mitigation_plan:
    - priority: medium_term
      action: Apply Lenovo security patches for the Baiying PC Client when released.
      owner: IT Operations
      addresses: CVE-2026-92629
      evidence: NVD vulnerability entry
---

A vulnerability identified as CVE-2026-92629 exists in the Lenovo Baiying PC Client, a software package distributed specifically within the Chinese market. The vulnerability is classified as an improper authorization flaw. It allows a local, authenticated user to interact with the application in a manner that bypasses existing access controls, leading to the execution of arbitrary code with elevated system privileges. This escalation of privilege significantly impacts the security posture of the host machine, as the attacker can perform operations reserved for administrative accounts. Given the local nature of the attack, this vulnerability is particularly relevant in multi-user environments or scenarios where non-privileged users have access to corporate workstations where this client is installed.

## Impact

Successful exploitation allows a local user to execute arbitrary code with elevated privileges, potentially leading to full system compromise. This represents a high risk in enterprise environments where users are not restricted from executing local applications or where shared workstations are deployed. The scope of impact is limited to the subset of Lenovo devices in the Chinese market running the vulnerable client software.

## Recommendation

Identify all endpoints running Lenovo Baiying PC Client within your environment and restrict local user access to the binary until an official vendor patch is applied.
