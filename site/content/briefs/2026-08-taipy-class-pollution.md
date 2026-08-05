---
title: Taipy Class Pollution Vulnerability Leading to RCE
slug: 2026-08-taipy-class-pollution
description: Taipy v4.0.3 contains a class pollution vulnerability (CVE-2025-30374) that allows unauthenticated attackers to manipulate server-side state via crafted WebSocket messages, resulting in RCE, credential leakage, XSS, and DoS.
date: "2026-08-05T21:29:20Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - jackfromeast
tags:
  - cve-2025-30374
  - rce
  - class-pollution
  - taipy
  - python
vendors:
  - Avaiga
products:
  - Taipy (4.0.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By overwriting the __SELF_VAR value through class pollution, an attacker can control the expression being evaluated, ultimately leading to arbitrary code execution.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=45087582-17AC-54B4-A395-D4B3F42789BA
  - https://cwe.mitre.org/data/definitions/915.html
iocs:
  - type: url
    value: https://webhook.site/0df4ac02-0b20-4ffc-bbda-287da8bc8a0a
ioc_counts:
  url: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Taipy instances to latest secure version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2025-30374 exists in v4.0.3.
  enrichment_needed:
    - item: CVE-2025-30374 patch availability
      owner: CTI
      reason: Ensure a fix is available from Avaiga before advising internal teams.
      evidence: Advisory mentions 4.0.3 is the latest version at discovery.
  hunt_leads:
    - lead: Search WebSocket logs for messages containing 'name' fields with '__class__' or '__base__' substrings.
      technique_id: T1059.003
      data_needed:
        - Application WebSocket logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates injection of malicious paths via 'name' field.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound internet access for servers running Taipy.
      owner: IT Operations
      addresses: Credential leakage/Exfiltration
      evidence: PoC shows ability to redirect outbound traffic to webhook.site.
---

A severe class pollution vulnerability, identified as CVE-2025-30374, exists in Taipy v4.0.3. The vulnerability stems from an insecure recursive state update mechanism in `taipy/gui/utils/_attributes.py`, where client-provided input is used to dynamically update object attributes without validation. Attackers can leverage this to inject malicious attribute paths (analogous to prototype pollution), effectively overwriting internal application state, module attributes, or class methods at runtime.

The impact is significant, as attackers can achieve Remote Code Execution (RCE) by manipulating the `Gui.__SELF_VAR` attribute used within internal `eval()` calls. Furthermore, the vulnerability enables credential exfiltration, such as OpenAI API tokens, by redirecting outbound application traffic, as well as enabling Reflected XSS and Denial of Service (DoS) by crashing the application or injecting malicious content into rendered responses. This flaw represents a critical security risk for any Taipy deployment exposing application state management to client-side input.

## Attack Chain

1. Attacker establishes a WebSocket connection to the targeted Taipy application.
2. Attacker crafts a malicious message payload containing an attribute path injection string (e.g., `_TpN_tpec_TpExPr...`).
3. The message is sent to the Taipy server, where it is processed by `_manage_message`.
4. The `_setscopeattr_drill` function is triggered, passing the attacker's input to the recursive `_attrsetter` function.
5. The `_attrsetter` function uses `setattr` and `getattr` to traverse and modify server-side object attributes based on the attacker's path.
6. Attacker targets specific internal attributes such as `Gui.__SELF_VAR` or method attributes on `_TaipyBase`.
7. Upon subsequent application logic execution, the modified attributes are accessed or evaluated (e.g., via `eval()`).
8. Final objective achieved: RCE, credential exfiltration, XSS injection, or application crash.

## Impact

The vulnerability affects Taipy v4.0.3 users. Successful exploitation allows for complete server compromise through RCE, theft of sensitive configuration secrets like OpenAI tokens, disruption of services via DoS, and potential account takeover via XSS. Given the availability of public proof-of-concept exploits, the risk to unpatched infrastructure is high.

## Recommendation

Prioritize the following actions to detect and mitigate CVE-2025-30374:

- Update Taipy to a patched version immediately upon vendor release.
- Implement strict server-side validation for all input parameters received via WebSocket messages in `_manage_message`.
- Block or inspect WebSocket traffic containing deeply nested attribute paths or sequences targeting internal application classes.
- Audit infrastructure logs for unauthorized WebSocket messages containing `__class__`, `__base__`, or `__SELF_VAR` patterns.
