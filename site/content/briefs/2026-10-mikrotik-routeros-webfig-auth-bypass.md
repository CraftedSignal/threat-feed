---
brief_id: brief-2026-10-21-mikrotik-routeros-webfig-auth-bypass
event_id: brief-2026-10-21-mikrotik-routeros-webfig-auth-bypass
revision: 1
activity_at: "2026-10-21T19:57:56Z"
title: 'MikroTik RouterOS: WebFig session token replay vulnerability (CVE-2026-89035)'
slug: 2026-10-mikrotik-routeros-webfig-auth-bypass
description: MikroTik RouterOS versions 7.24.5 and earlier contain a session token replay vulnerability in the WebFig interface that allows unauthenticated attackers to hijack administrative sessions.
date: "2026-10-21T19:57:56Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - session-hijacking
  - network-security
  - cve-2026-89035
vendors:
  - MikroTik
products:
  - RouterOS (<= 7.24.5)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.002
    subtechnique_name: Pass the Hash
    evidence: This allows an attacker to reuse intercepted session tokens to bypass authentication and gain administrative access, which persists until the token store is cleared.
    confidence_band: high
cves:
  - id: CVE-2025-61481
    cvss: 10
    epss: 0.00304
    kev_status: "false"
  - id: CVE-2026-89035
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89035
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict WebFig management interface access to trusted IP ranges
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated session replay; network isolation mitigates exposure.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest RouterOS firmware once a patch addressing CVE-2026-89035 is available
      owner: IT Operations
      addresses: CVE-2026-89035
      evidence: Vulnerability resides in libucrypto.so logic.
---

MikroTik RouterOS versions through 7.24.5 are vulnerable to a session token replay attack within the WebFig interface. The vulnerability arises from the 'makeSessionKey' function in 'libucrypto.so', which generates session tokens using fixed, predictable salts. Because the implementation fails to incorporate session-specific or channel-specific input, tokens are not bound to the ECDH session used during initial authentication. Attackers who capture valid session tokens can replay them to bypass authentication and achieve administrative access. This access remains persistent until the router's internal token store is explicitly cleared. This finding builds upon the transport-layer weaknesses previously identified in CVE-2025-61481.

## Impact
Successful exploitation allows for unauthorized administrative access to the affected MikroTik router. Attackers can maintain persistent control over the device and its configuration until the administrative session store is manually cleared.

## Recommendation
- Inventory all internet-facing or sensitive management interfaces running MikroTik RouterOS 7.24.5 or older.
- Restrict access to the WebFig management interface to trusted management networks using firewall rules.
- Monitor for administrative account usage originating from unexpected source IP addresses or irregular timeframes.
- Verify the availability of firmware updates from MikroTik that address the 'makeSessionKey' implementation in 'libucrypto.so' and apply them as a priority.
