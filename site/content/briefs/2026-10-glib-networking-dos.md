---
brief_id: brief-2026-10-30-glib-networking-dos
event_id: brief-2026-10-30-glib-networking-dos
revision: 1
activity_at: "2026-10-30T07:20:10Z"
title: 'GNOME glib-networking: TLS 1.3 session cache memory exhaustion (CVE-2026-103963)'
slug: 2026-10-glib-networking-dos
description: A vulnerability in glib-networking allows a malicious TLS 1.3 server to trigger unbounded memory consumption in client applications via excessive session ticket messages, leading to a denial-of-service condition.
date: "2026-10-30T07:20:10Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:gnome:glib-networking:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - glib-networking
vendors:
  - GNOME
products:
  - glib-networking
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A malicious server can exploit this by sending excessive session ticket messages, causing the client application to continuously consume memory. This unbounded memory growth can exhaust system memory, resulting in a Denial of Service (DoS).
    confidence_band: high
cves:
  - id: CVE-2026-103963
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103963
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Identify client applications exhibiting anomalous memory growth patterns following network activity
      technique_id: T1499
      data_needed:
        - Endpoint memory usage monitoring (e.g., resident set size)
        - Network connection logs for TLS 1.3 handshakes
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: The flaw results in unbounded memory growth in the client application.
  mitigation_plan:
    - priority: immediate
      action: Patch glib-networking to the latest vendor-supplied version to remediate CVE-2026-103963
      owner: IT Operations
      addresses: CVE-2026-103963
      evidence: NVD vulnerability disclosure
---

CVE-2026-103963 is a memory exhaustion vulnerability in glib-networking. When a client performs a TLS 1.3 handshake, the library fails to limit the number of session tickets retained in the client-side session cache for a specific host. A malicious server can send an excessive number of session ticket messages during the handshake process, forcing the client application to continuously allocate memory. This behavior leads to memory exhaustion and potential crash of the client application, resulting in a Denial of Service.

## Impact

Successful exploitation results in a Denial of Service (DoS) for any application utilizing the affected glib-networking library, caused by the exhaustion of system memory resources.

## Recommendation

Identify and patch instances of glib-networking to the latest available version provided by the distribution or GNOME project. Prioritize patching client applications that frequently initiate TLS connections to untrusted or external endpoints, as these are the primary vectors for this memory exhaustion attack.
