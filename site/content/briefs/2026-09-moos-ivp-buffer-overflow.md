---
title: Buffer Overflow Vulnerabilities in MOOS-IvP
slug: 2026-09-moos-ivp-buffer-overflow
description: Multiple buffer overflow vulnerabilities in MOOS-IvP versions up to 24.8.1 allow for remote code execution via malformed IvP function strings.
date: "2026-09-03T23:25:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:moos_ivp:moos_ivp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - rce
  - memory-corruption
vendors:
  - MOOS-IvP
products:
  - MOOS-IvP (<= 24.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Attackers can craft malicious encoded strings with mismatched declared and actual field lengths to overflow heap and stack buffers, potentially achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85437
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85437
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade MOOS-IvP to version 24.8.2 or later
      owner: IT Operations
      addresses: CVE-2026-85437
      evidence: NVD vulnerability disclosure identifies the issue as present in versions through 24.8.1.
---

MOOS-IvP through version 24.8.1 contains multiple buffer overflow vulnerabilities located within its IvP function string decoders. The vulnerability arises due to the application's failure to adequately validate length fields provided in attacker-controlled input. By crafting malicious encoded strings where the declared field length differs significantly from the actual field length, an attacker can induce heap or stack buffer overflows. These memory corruption events can be leveraged to achieve arbitrary remote code execution. The vulnerability is triggered when the affected components process malicious MOOS variables or malformed alog files, which are central to the MOOS-IvP communication and logging architecture. Defenders should prioritize patching, as these vulnerabilities are classified with a CVSS v3.1 base score of 9.8, indicating high potential for exploitation.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code with the privileges of the MOOS-IvP process. In many deployments, these processes operate within critical autonomous systems or research environments. If exploited, an attacker could gain persistent access, exfiltrate sensitive mission data, or disrupt the operation of underwater autonomous vehicles and other marine robotic systems using the MOOS-IvP framework.

## Recommendation

- Upgrade all instances of MOOS-IvP to version 24.8.2 or later to address the vulnerable IvP function string decoders identified in CVE-2026-85437.
- Audit all external inputs feeding into MOOS variables and restrict access to alog files to trusted administrative users only.
- Monitor process integrity for abnormal crashes or memory access violations that might indicate attempted exploitation of these buffer overflows.
