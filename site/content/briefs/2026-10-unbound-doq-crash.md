---
brief_id: brief-2026-10-21-unbound-doq-crash
event_id: brief-2026-10-21-unbound-doq-crash
revision: 1
activity_at: "2026-10-21T11:19:29Z"
title: 'NLnet Labs Unbound: DNS-over-QUIC use-after-free (CVE-2026-97206)'
slug: 2026-10-unbound-doq-crash
description: NLnet Labs Unbound versions 1.22.0 through 1.26.1 contain a use-after-free vulnerability in the DNS-over-QUIC implementation, allowing a remote attacker to cause a service crash via QUIC path migration.
date: "2026-10-21T11:19:29Z"
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
cpes:
  - cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*
vendors:
  - NLnet Labs
products:
  - Unbound (1.22.0-1.26.1)
cves:
  - id: CVE-2026-97206
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97206
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Unbound to the latest version covering CVE-2026-97206
      owner: IT Operations
      due: 72h
      evidence: Vulnerability requires patching per standard security advisory
  mitigation_plan:
    - priority: immediate
      action: Disable DNS-over-QUIC if not required for business operations until patching is completed
      owner: IT Operations
      addresses: CVE-2026-97206
      evidence: Source notes vulnerability is specific to DoQ implementation
---

NLnet Labs Unbound versions 1.22.0 through 1.26.1 are affected by a use-after-free vulnerability (CVE-2026-97206) in the DNS-over-QUIC (DoQ) handling. When configured for multi-threaded operation, a remote attacker can trigger a QUIC path migration that initiates stream and connection cleanup. Because a mesh reply retains a pointer to the DoQ stream, the cleanup process frees the memory prematurely. When the mesh reply completes, it attempts to dereference the stale pointer, resulting in a service crash.

## Impact
Successful exploitation results in a Denial of Service (DoS) due to the Unbound service crashing.

## Recommendation
- Upgrade NLnet Labs Unbound to a version addressing CVE-2026-97206.
- Review network configurations to identify instances of Unbound utilizing DNS-over-QUIC.
- Monitor Unbound service logs and system daemon logs for repeated crash and restart events associated with DoQ activity.
