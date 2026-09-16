---
title: CVE-2026-92717 Authentication Bypass in Covenant
slug: 2026-09-covenant-auth-bypass
description: Covenant versions 0.6 and earlier contain an authentication bypass vulnerability allowing unauthenticated remote actors to gain full operator API access via the CovenantHub SignalR hub.
date: "2026-09-16T19:51:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:covenant:covenant:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - c2-infrastructure
  - cve-2026-92717
vendors:
  - Covenant
products:
  - Covenant (<= 0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558.001
    technique_name: Golden Ticket
    evidence: The missing Authorize attribute on the CovenantHub SignalR hub allows unauthenticated callers to receive a signed JWT token, which can then be leveraged to authenticate as a legitimate operator.
    confidence_band: high
cves:
  - id: CVE-2026-92717
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92717
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the Covenant management UI/API.
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability report details critical authentication bypass.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Covenant to the latest patched version.
      owner: IT Operations
      addresses: CVE-2026-92717
      evidence: NVD vulnerability disclosure.
---

Covenant versions 0.6 and earlier suffer from a critical authentication bypass vulnerability (CVE-2026-92717) due to a missing 'Authorize' attribute on the 'CovenantHub' SignalR hub. This oversight permits unauthenticated network callers to invoke the 'CreateHttpListener' method, which returns a valid signed JWT token. An attacker who successfully calls this method can use the returned token to authenticate against the Covenant operator API. This grants the attacker full control over the C2 infrastructure, including the ability to manage grunts, access stored credentials, modify binaries, and exfiltrate sensitive operational data and event logs. Because the vulnerability involves a core architectural flaw in the SignalR hub configuration, it significantly lowers the barrier for unauthorized parties to hijack a Covenant deployment. Defenders should prioritize patching or restricting access to the Covenant management interface.

## Impact

Successful exploitation allows full administrative control over the Covenant C2 framework. An attacker can access all grunts, exfiltrate credentials gathered from target environments, modify or deploy malicious binaries, and retrieve operator roster and event history. This provides an attacker with the ability to maintain persistence, escalate privileges, and steal data harvested by the C2 platform.

## Recommendation

* Restrict network access to the Covenant management interface using network firewalls or VPNs until the software is updated.
* Patch Covenant instances to a version addressing CVE-2026-92717 immediately.
* Monitor SignalR traffic to the Covenant hub for unauthenticated calls to the 'CreateHttpListener' method.
