---
title: Heap-Based Buffer Overflow in snac2 via Malformed JSON
slug: 2026-10-snac2-heap-overflow
description: An unauthenticated heap-based buffer overflow in snac2 versions before 2.93 allows remote attackers to trigger memory corruption via a specially crafted JSON payload.
date: "2026-10-18T12:22:12Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:snac2:snac2:*:*:*:*:*:*:*:*
vendors:
  - snac2
products:
  - snac2 (< 2.93)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: "An unauthenticated remote attacker can trigger this vulnerability by sending a crafted JSON string containing a \0 escape sequence within an application/activity+json POST request to the activitypub_post_handler."
    confidence_band: high
cves:
  - id: CVE-2026-112021
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112021
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade snac2 to 2.93 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112021 patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade snac2 to 2.93
      owner: IT Operations
      addresses: CVE-2026-112021
      evidence: NVD advisory for CVE-2026-112021
---

The activitypub server snac2 contains a heap-based buffer overflow vulnerability (CVE-2026-112021) in the _xs_json_load_lexer() function. This vulnerability affects all versions prior to 2.93. The flaw exists because the JSON parser fails to properly handle the \u0000 (null byte) escape sequence, leading to heap memory corruption. An unauthenticated, remote attacker can exploit this by submitting a crafted application/activity+json payload to the activitypub_post_handler endpoint. Notably, the vulnerability is triggered during the parsing phase, which occurs before the application performs cryptographic signature verification on incoming ActivityPub messages. Successful exploitation typically results in a process crash, leading to a denial-of-service condition for the affected instance.

## Impact

The vulnerability allows unauthenticated attackers to remotely crash snac2 servers. This poses a significant availability risk for organizations and individuals relying on snac2 for federated networking. Because the vulnerability is triggered prior to authentication or signature verification, it is highly accessible to any network-adjacent entity capable of reaching the activitypub_post_handler interface.

## Recommendation

1. Upgrade all instances of snac2 to version 2.93 or later to patch CVE-2026-112021.
2. Implement network ingress filtering to limit access to ActivityPub handling endpoints to trusted federated peers, if immediate patching is not possible.
3. Monitor application error logs for repeated segmentation faults or process crashes specifically occurring within the JSON parsing routines of the ActivityPub handler.
