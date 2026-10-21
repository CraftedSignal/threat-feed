---
brief_id: brief-2026-10-21-ntpsec-dos
event_id: brief-2026-10-21-ntpsec-dos
revision: 1
activity_at: "2026-10-21T17:10:06Z"
title: 'NTPsec ntpd: Out-of-bounds read in NTS extension field parsing (CVE-2026-102486)'
slug: 2026-10-ntpsec-dos
description: NTPsec ntpd versions 1.1.4 through 1.2.5 are vulnerable to a remote denial-of-service attack due to an out-of-bounds read flaw triggered by malformed NTS extension fields.
date: "2026-10-21T17:10:06Z"
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
  - cpe:2.3:a:ntpsec:ntpd:1.1.4:*:*:*:*:*:*:*
  - cpe:2.3:a:ntpsec:ntpd:1.2.5:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - ntpsec
  - vulnerability
vendors:
  - NTPsec
products:
  - ntpd (1.1.4 through 1.2.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote attacker can trigger this vulnerability by sending a maliciously crafted NTS Authenticator and Encrypted Extension Fields (AEEF) field containing an oversized nonce length, resulting in a denial-of-service condition that crashes the daemon.
    confidence_band: high
cves:
  - id: CVE-2026-102486
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102486
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all servers running affected versions of NTPsec ntpd.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects NTPsec ntpd 1.1.4 through 1.2.5.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest non-vulnerable version of NTPsec ntpd as soon as available.
      owner: IT Operations
      addresses: CVE-2026-102486
      evidence: Patch required to address out-of-bounds read vulnerability.
---

NTPsec ntpd versions 1.1.4 through 1.2.5 contain a vulnerability in the parsing of Network Time Security (NTS) extension fields. An unauthenticated remote attacker can send a crafted NTS Authenticator and Encrypted Extension Fields (AEEF) field containing an oversized nonce length. This triggers an out-of-bounds read, causing the ntpd daemon to crash. There is currently no mention of remote code execution or authentication bypass.

## Impact

Successful exploitation results in a denial-of-service (DoS) condition, as the ntpd daemon crashes when processing the malformed AEEF packet.

## Recommendation

1. Inventory all systems running NTPsec ntpd 1.1.4 through 1.2.5.
2. Monitor for anomalous ntpd crash events or sudden service restarts on internet-facing time synchronization servers.
3. Patch to the latest stable release of NTPsec ntpd once the vendor provides a resolution.
