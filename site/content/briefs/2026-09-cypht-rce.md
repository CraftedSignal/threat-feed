---
title: PHP Object Injection in Cypht
slug: 2026-09-cypht-rce
description: Cypht versions before 2.12.2 contain a PHP object injection vulnerability in the logout handler, allowing authenticated attackers to achieve remote code execution via serialized payloads.
date: "2026-09-01T23:09:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cypht:cypht:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - php
  - rce
vendors:
  - Cypht
products:
  - Cypht (< 2.12.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can pass a base64-encoded serialized payload through this parameter... enabling gadget-chain exploitation to achieve remote code execution as the web server process.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Cypht before 2.12.2 contains a PHP object injection vulnerability that allows authenticated attacker... to execute arbitrary operating system commands.
    confidence_band: high
cves:
  - id: CVE-2026-71981
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71981
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Cypht to 2.12.2 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-71981 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cypht to 2.12.2
      owner: IT Operations
      addresses: CVE-2026-71981
      evidence: Source support
---

Cypht versions prior to 2.12.2 are vulnerable to a PHP object injection flaw. The vulnerability resides in the application's logout handler, specifically within the processing of the 'back_query' GET parameter. An authenticated attacker can supply a malicious, base64-encoded serialized PHP object graph. The application decodes and passes this input directly to the PHP unserialize() function without implementing an allow-list, signature verification, or proper type restrictions. This lack of validation allows attackers to trigger gadget-chain exploitation, resulting in remote code execution (RCE) with the privileges of the web server process. Defenders should prioritize patching affected Cypht instances to version 2.12.2 or later to mitigate this risk.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary system commands on the underlying host, leading to full compromise of the web server, potential lateral movement within the network, and exfiltration of sensitive application data.

## Recommendation

1. Upgrade all Cypht instances to version 2.12.2 or later immediately to patch CVE-2026-71981.
2. Monitor web server access logs for anomalous requests to the logout handler containing base64-encoded strings within the 'back_query' parameter.
3. Implement strict request validation for all parameters passed to deserialization functions within the environment.
