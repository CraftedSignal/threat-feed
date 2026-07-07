---
title: OpenClaw Message Read Action Authorization Bypass (CVE-2026-53815)
slug: 2026-07-openclaw-auth-bypass
description: A high-severity vulnerability (CVE-2026-53815) in OpenClaw's message read actions allows lower-trust callers to bypass channel allowlist checks, potentially exposing sensitive messages from unintended channels to unauthorized parties.
date: "2026-07-03T12:21:36Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - authorization-bypass
  - openclaw
  - npm
vendors:
  - OpenClaw
products:
  - OpenClaw (npm/openclaw)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a lower-trust caller with access to the affected message read action could request messages without the same channel allowlist check used by normal delivery.
    confidence_band: high
cves:
  - id: CVE-2026-53815
    cvss: 6.5
    epss: 0.00215
references:
  - https://github.com/advisories/GHSA-q7q8-3mgw-q67r
---

A high-severity authorization bypass vulnerability, identified as CVE-2026-53815, has been disclosed in OpenClaw, affecting versions up to and including `2026.5.19-beta.2`. This flaw allows a lower-trust caller, who has access to an affected message read action, to bypass critical channel allowlist checks that are normally applied to message delivery. Consequently, such an actor could request and gain access to messages from channels they are not authorized to view. The first stable patched version addressing this issue is `2026.5.19`. The practical impact of this vulnerability is contingent on specific operator configurations, particularly whether the affected feature is enabled and accessible by lower-trust input within the environment. This vulnerability primarily affects the integrity and confidentiality of messages within the OpenClaw platform.

## Impact

When the vulnerable feature is enabled and accessible by lower-trust callers, this flaw could lead to the unintended exposure of messages from channels that were not authorized for that caller. The severity of the impact is highly dependent on the specific operator's OpenClaw configuration and the sensitivity of the messages managed by the system. While no active exploitation is confirmed, successful exploitation could result in unauthorized disclosure of sensitive internal communications or data, potentially leading to compliance violations, data breaches, and reputational damage for affected organizations.

## Recommendation

*   Patch CVE-2026-53815 immediately by upgrading to OpenClaw version `2026.5.19` or later to remediate the vulnerability described in this brief.
*   Limit message read actions to trusted operators, as referenced in the GHSA advisory, to reduce the attack surface.
*   Keep channel and tool allowlists narrow and review them regularly, as recommended in the mitigation section of this brief.
*   Avoid sharing a single OpenClaw Gateway between mutually untrusted users.
*   Disable the affected feature when it is not strictly needed within your operational environment.
