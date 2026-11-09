---
brief_id: brief-2026-11-09-mit-kerberos-dos
event_id: brief-2026-11-09-mit-kerberos-dos
revision: 1
activity_at: "2026-11-09T21:57:46Z"
title: 'MIT Kerberos 5: Denial of Service via SEQUENCE OF array growth (CVE-2026-119079)'
slug: 2026-11-mit-kerberos-dos
description: A vulnerability in MIT Kerberos 5 (krb5) versions 1.11 and later allows remote, unauthenticated attackers to cause a denial of service on a Key Distribution Center (KDC) via excessive CPU consumption.
date: "2026-11-09T21:57:46Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:mit:kerberos_5:*:*:*:*:*:*:*:*
vendors:
  - MIT
products:
  - Kerberos 5 (>= 1.11)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: allows remote attackers to cause a denial of service (CPU consumption in the KDC)
    confidence_band: high
cves:
  - id: CVE-2026-119079
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119079
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory and patch systems running vulnerable MIT Kerberos 5 versions
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-119079 vulnerability in krb5 >= 1.11
  hunt_leads:
    - lead: Monitor for KDC process CPU spikes coincident with high rates of incoming TCP/88 traffic
      technique_id: T1499
      data_needed:
        - KDC process resource utilization
        - TCP connection metrics on port 88
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: exploitation causes CPU consumption in the KDC
  mitigation_plan:
    - priority: immediate
      action: Restrict KDC access (TCP/88) to trusted network segments
      owner: IT Operations
      addresses: CVE-2026-119079
      evidence: remote unauthenticated attackers can trigger CPU consumption
---

The function decode_sequence_of() in lib/krb5/asn.1/asn1_encode.c within MIT Kerberos 5 (krb5) versions 1.11 and later suffers from inefficient array growth management. A remote, unauthenticated attacker can exploit this by sending a specially crafted AS-REQ or TGS-REQ message containing a large number of elements within a SEQUENCE OF field over TCP. This triggers excessive CPU usage on the Key Distribution Center (KDC), resulting in a denial of service condition.

## Impact

Successful exploitation results in KDC service unavailability due to CPU exhaustion, preventing legitimate authentication requests across the Kerberos domain.

## Recommendation

- Identify all hosts running MIT Kerberos 5 (krb5) version 1.11 or later in the environment.
- Monitor for security updates from the MIT Kerberos consortium or operating system distribution vendors and apply patches as they become available.
- Until patched, restrict network access to the KDC (typically port 88 TCP) to known, trusted subnets to limit the attack surface for remote, unauthenticated exploitation.
