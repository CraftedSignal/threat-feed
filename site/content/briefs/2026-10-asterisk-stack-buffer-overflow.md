---
brief_id: brief-2026-10-27-asterisk-stack-buffer-overflow
event_id: brief-2026-10-27-asterisk-stack-buffer-overflow
revision: 1
activity_at: "2026-10-27T18:06:04Z"
title: 'Asterisk: H.323 channel driver stack buffer overflow (CVE-2026-57201)'
slug: 2026-10-asterisk-stack-buffer-overflow
description: A stack buffer overflow in the Asterisk chan_ooh323 module allows a remote attacker to crash the telephony process via a crafted H.323 packet.
date: "2026-10-27T18:06:04Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:asterisk:asterisk:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - buffer-overflow
  - telephony
vendors:
  - Asterisk
products:
  - Asterisk (< 20.20.1, < 21.12.3, < 22.10.1, < 23.4.1)
  - Certified Asterisk (< 20.7-cert11, < 22.8-cert3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remote attacker may send a carefully crafted packet that causes the Asterisk process to crash.
    confidence_band: high
cves:
  - id: CVE-2026-57201
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57201
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected Asterisk instances to the specified version
      owner: IT Operations
      due: 72h
      evidence: This issue is fixed in Asterisk 20.20.1, 21.12.3, 22.10.1, 23.4.1 and Certified Asterisk 20.7-cert11, 22.8-cert3.
  hunt_leads:
    - lead: Identify systems with the chan_ooh323 module active
      technique_id: T1498
      data_needed:
        - Asterisk module configuration files (modules.conf)
        - Asterisk CLI output (module show like ooh323)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The chan_ooh323 addon channel driver must be explicitly compiled and installed, which is not the default
  mitigation_plan:
    - priority: immediate
      action: Apply network firewall rules to restrict access to H.323 ports
      owner: Network Engineering
      addresses: CVE-2026-57201
      evidence: its port must be publicly reachable
---

A vulnerability (CVE-2026-57201) exists in the Asterisk `chan_ooh323` module's `ooTrace()` function. The function utilizes an unbounded `vsprintf` call to write data into a fixed 2048-byte stack buffer. A remote, unauthenticated attacker can trigger a crash of the Asterisk process by sending a specially crafted H.323 packet. 

This vulnerability only affects deployments where the `chan_ooh323` addon channel driver is explicitly compiled, installed, and exposed to the network.

## Impact

Successful exploitation results in a denial-of-service (DoS) condition, crashing the Asterisk telephony process.

## Recommendation

- Upgrade Asterisk to version 20.20.1, 21.12.3, 22.10.1, 23.4.1 or later.
- Upgrade Certified Asterisk to version 20.7-cert11, 22.8-cert3 or later.
- If upgrading is not immediately possible, disable the `chan_ooh323` module if it is not required for business operations.
- Restrict network access to H.323 listening ports via firewall rules to ensure only trusted sources can reach the service.
