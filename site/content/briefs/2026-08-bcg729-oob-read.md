---
title: Out-of-Bounds Read in Belledonne Communications bcg729
slug: 2026-08-bcg729-oob-read
description: An out-of-bounds read vulnerability in bcg729 versions up to 1.1.2 allows unauthenticated network-adjacent attackers to cause a process crash or heap memory exposure via malformed RTP payloads.
date: "2026-08-17T18:50:22Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Belledonne Communications
products:
  - bcg729 (<= 1.1.2)
cves:
  - id: CVE-2026-71980
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71980
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade bcg729 to version 1.1.3 or later to remediate CVE-2026-71980
      owner: IT Operations
      due: 72h
      evidence: Source document identifies version <= 1.1.2 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Review deployment inventory for instances of bcg729 library
      owner: IT Operations
      addresses: CVE-2026-71980
      evidence: Vulnerability affects bcg729 media processing
---

Belledonne Communications bcg729 versions up to 1.1.2 are susceptible to an out-of-bounds read vulnerability located in the decodeSIDframe() function within src/cng.c. The vulnerability is triggered by a network-adjacent attacker sending a specifically crafted, zero-length comfort-noise RTP payload. When processed, this payload causes an integer underflow in the filter order calculation. The resulting value wraps to 255 and is subsequently clamped to 10. Consequently, the function attempts to read 11 bytes from a buffer that contains zero bytes. This behavior leads to either the termination of the media processing component (Denial of Service) or the potential leakage of adjacent heap memory, which is then incorrectly interpreted as reflection coefficients. This vulnerability is significant for organizations deploying real-time communication infrastructure utilizing the bcg729 library.

## Impact

Successful exploitation of this vulnerability results in the disruption of media processing services, causing a Denial of Service for affected voice/video communication applications. Additionally, the out-of-bounds read condition poses an information disclosure risk, as adjacent heap memory contents may be consumed and processed as valid media data.

## Recommendation

- Upgrade the bcg729 library to the latest version, ensuring all dependencies are updated.
- Monitor network traffic for malformed RTP packets with zero-length payloads directed at telephony or media processing endpoints.
- Prioritize patching for systems acting as publicly reachable SIP or RTP gateways that utilize the affected library version.
