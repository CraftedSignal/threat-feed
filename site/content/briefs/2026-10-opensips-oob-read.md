---
title: Out-of-Bounds Read in OpenSIPS rtpproxy Component
slug: 2026-10-opensips-oob-read
description: OpenSIPS versions 3.6.8 and 4.0.1 and earlier are vulnerable to a remote out-of-bounds read in the rtpproxy_offer and rtpproxy_answer functions, which can lead to denial-of-service or information disclosure.
date: "2026-10-14T22:33:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opensips:opensips:*:*:*:*:*:*:*:*
vendors:
  - OpenSIPS
products:
  - OpenSIPS (<= 3.6.8, <= 4.0.1)
cves:
  - id: CVE-2026-110679
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110679
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenSIPS to version 3.6.9 or 4.0.2
      owner: IT Operations
      due: 48h
      evidence: Source explicitly advises upgrading to resolve the issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSIPS to 3.6.9 or 4.0.2
      owner: IT Operations
      addresses: CVE-2026-110679
      evidence: 'Source: Upgrading to version 3.6.9 and 4.0.2 is sufficient to resolve this issue.'
---

OpenSIPS versions up to 3.6.8 and 4.0.1 contain a vulnerability (CVE-2026-110679) within the rtpproxy module, specifically involving the rtpproxy_offer and rtpproxy_answer functions. An unauthenticated remote attacker can trigger an out-of-bounds read by sending crafted SIP packets that interact with the RTP proxy functionality. Successful exploitation of this vulnerability may lead to a denial-of-service (DoS) condition or potential information disclosure of process memory. The issue stems from insufficient input validation when processing RTP proxy control commands. Defenders should prioritize patching OpenSIPS instances to versions 3.6.9 or 4.0.2 to remediate this vulnerability.

## Impact

The vulnerability poses a high risk to telephony infrastructure relying on OpenSIPS for RTP relay services. If exploited, an attacker can crash the OpenSIPS process, causing a denial-of-service for voice and media traffic, or potentially leak sensitive information stored in the memory space accessed by the out-of-bounds read. This impact is significant for VoIP service providers and enterprise communication systems.

## Recommendation

- Upgrade OpenSIPS to version 3.6.9 or 4.0.2 immediately to patch CVE-2026-110679.
- Inspect network traffic logs for malformed or unusually large RTP proxy command packets targeting OpenSIPS infrastructure.
- Restrict network access to the OpenSIPS management interfaces to trusted IP ranges to mitigate the risk of remote exploitation by unauthenticated actors.
