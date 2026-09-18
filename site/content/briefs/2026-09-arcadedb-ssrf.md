---
title: SSRF Vulnerability in ArcadeDB via IPv6 Transition Addressing
slug: 2026-09-arcadedb-ssrf
description: Authenticated attackers can exploit a validation flaw in ArcadeDB's SSRF guard to reach internal services or cloud metadata endpoints by using specifically crafted IPv6 transition addresses.
date: "2026-09-18T16:07:43Z"
lastmod: "2026-09-18T18:07:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:arcadedata:arcadedb:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - database
  - access-control
vendors:
  - ArcadeData
products:
  - ArcadeDB (< 26.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can supply URLs resolving to NAT64, 6to4, or Teredo addresses embedding RFC 1918 or loopback IPv4 payloads to reach internal services and cloud metadata endpoints.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated low-privilege user can read or insert TimeSeries samples despite explicit deny rules by exploiting the missing type-name-based access check.
    confidence_band: high
cves:
  - id: CVE-2026-93597
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93597
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93593
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade ArcadeDB to 26.9.1 or later
      owner: IT Operations
      due: 72h
      evidence: Source explicitly mandates version 26.9.1 for the fix.
  mitigation_plan:
    - priority: immediate
      action: Egress filtering for database server
      owner: Network Security
      addresses: CVE-2026-93597
      evidence: Network controls mitigate SSRF impacts.
updates:
  - at: "2026-09-18T18:07:08Z"
    level: L2
    summary: added coverage for ArcadeDB (< 26.9.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93593
---

ArcadeDB versions prior to 26.9.1 contain an SSRF vulnerability within the security guards protecting the 'IMPORT DATABASE' and internal server commands. The vulnerability stems from the application's failure to properly validate IPv6 transition mechanisms, such as NAT64, 6to4, and Teredo, when parsing user-supplied URLs. 

An authenticated attacker can abuse this deficiency by embedding RFC 1918 private IPv4 addresses or loopback addresses within these transition-style IPv6 addresses. When processed by the server, these payloads bypass the existing SSRF protection, forcing the ArcadeDB service to initiate outbound requests to unauthorized internal network destinations or cloud provider metadata services (e.g., 169.254.169.254). This can lead to information disclosure or the exploitation of other internal services that trust requests originating from the database host.

## Impact

Successful exploitation allows an authenticated attacker to bypass network segmentation and interact with internal-only services or cloud-native metadata APIs. This could result in the exfiltration of sensitive configuration data, cloud environment credentials, or the execution of unauthorized actions against internal infrastructure, depending on the services accessible to the ArcadeDB instance.

## Recommendation

- Upgrade ArcadeDB to version 26.9.1 or later to implement the corrected IPv6 address validation logic.
- Implement egress filtering at the network level to restrict database server access to only necessary external endpoints.
- Monitor database command logs for anomalous 'IMPORT DATABASE' or server management requests originating from non-administrative users.
- Restrict access to internal metadata endpoints (e.g., 169.254.169.254) from the network segment where the database resides.
