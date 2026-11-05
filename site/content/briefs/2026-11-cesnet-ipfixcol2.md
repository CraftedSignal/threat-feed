---
brief_id: brief-2026-11-04-cesnet-ipfixcol2
event_id: brief-2026-11-04-cesnet-ipfixcol2
revision: 2
activity_at: "2026-11-05T00:08:59Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:08:59Z"
    checksum: sha256:f43b30daf5373c8bc9c746cbe18637ad3f0245d99a489a6364470a4168ab598c
    summary: added CVE-2026-122127
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122127
title: 'CESNET ipfixcol2: Heap buffer overflow in Forwarder output plugin (CVE-2026-122130)'
slug: 2026-11-cesnet-ipfixcol2
description: An integer overflow vulnerability in the CESNET ipfixcol2 Forwarder output plugin allows unauthenticated remote attackers to trigger heap memory corruption via crafted IPFIX messages.
date: "2026-11-04T22:07:43Z"
lastmod: "2026-11-05T00:06:15Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:cesnet:ipfixcol2:*:*:*:*:*:*:*:*
vendors:
  - CESNET
products:
  - ipfixcol2 (< 2.9.0)
  - ipfixcol2 (2.7.1-2.8.9)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can send near-65535-byte data sets and large templates to a collector forwarding over TCP to crash it and perform 2-byte writes to attacker-influenced addresses.
    confidence_band: high
cves:
  - id: CVE-2026-122130
    cvss: 8.2
    kev_status: "false"
  - id: CVE-2026-122127
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122130
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122127
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ipfixcol2 to version 2.9.0 or later on all collector instances.
      owner: IT Operations
      due: 48h
      evidence: Source notes version 2.3.0 before 2.9.0 is vulnerable.
  hunt_leads:
    - lead: Investigate process crash telemetry for ipfixcol2 service instances.
      technique_id: T1203
      data_needed:
        - System audit logs
        - Application crash dumps
        - Service management logs (systemd)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can send near-65535-byte data sets and large templates to a collector forwarding over TCP to crash it.
  mitigation_plan:
    - priority: immediate
      action: Implement access control lists on the network layer to limit IPFIX collector TCP port access to authorized exporter IPs.
      owner: IT Operations
      addresses: CVE-2026-122130
      evidence: Vulnerability allows unauthenticated IPFIX exporters to overflow a heap buffer.
updates:
  - at: "2026-11-05T00:06:15Z"
    level: L2
    summary: added CVE-2026-122127
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122127
---

CESNET ipfixcol2 versions 2.3.0 through 2.8.x are vulnerable to an integer overflow within the Forwarder output plugin. An unauthenticated attacker can send specially crafted IPFIX data sets and templates over TCP to the collector. The vulnerability stems from the wrapping of uint16_t message length counters, which results in a heap buffer overflow. This can be exploited to crash the collector service or potentially execute 2-byte writes to arbitrary memory addresses controlled by the attacker.

## Impact

Successful exploitation may lead to a denial-of-service (crash) or arbitrary memory corruption via 2-byte writes to memory addresses influenced by the attacker.

## Recommendation

- Upgrade ipfixcol2 to version 2.9.0 or later to include the fix for the integer overflow in the Forwarder plugin.
- Until patching is possible, restrict access to the IPFIX collector TCP ports to trusted IPFIX exporters using firewall rules.
- Monitor logs for repeated collector service crashes or restarts that coincide with incoming IPFIX traffic.
