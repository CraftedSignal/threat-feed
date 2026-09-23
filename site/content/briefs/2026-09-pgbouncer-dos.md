---
title: Multiple Denial of Service Vulnerabilities in PgBouncer
slug: 2026-09-pgbouncer-dos
description: Multiple vulnerabilities in PgBouncer allow a remote, unauthenticated attacker to trigger a Denial of Service condition, impacting the availability of the connection pooler.
date: "2026-09-23T19:55:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - database-security
  - vulnerability-management
vendors:
  - PgBouncer
products:
  - PgBouncer
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in PgBouncer ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3529
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all instances of PgBouncer across the production environment
      owner: IT Operations
      due: 48h
      evidence: General security requirement to assess exposure to identified vulnerabilities.
  enrichment_needed:
    - item: Specific CVEs and fixed versions
      owner: CTI
      reason: The advisory does not yet list specific CVEs or patch versions required for remediation.
      evidence: Source provided lacks granular vulnerability technical details.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade PgBouncer to the latest stable release once vendor provides patched versions
      owner: IT Operations
      addresses: Potential DoS vulnerability
      evidence: Standard remediation for identified software flaws.
---

The BSI has released a security advisory regarding multiple vulnerabilities identified in PgBouncer, a connection pooler for PostgreSQL. These vulnerabilities can be exploited by a remote, unauthenticated attacker to cause a Denial of Service (DoS) condition. By sending specially crafted requests, an attacker can crash the PgBouncer process or render it unresponsive to legitimate database traffic. This impacts the availability of backend database services that rely on PgBouncer for connection management. Defenders should note that these vulnerabilities are exploitable over the network without requiring prior authentication. Given the critical role of connection poolers in database architecture, organizations utilizing PgBouncer should prioritize checking their installed versions against vendor-supplied security patches to mitigate potential service disruptions.

## Impact

The successful exploitation of these vulnerabilities results in a Denial of Service, which effectively blocks access to the backend PostgreSQL database for all applications relying on the affected PgBouncer instance. This leads to service outages for any systems dependent on the database, potentially causing widespread application downtime across the affected infrastructure.

## Recommendation

Prioritize the identification of all PgBouncer instances within the enterprise environment. Monitor vendor security advisories for the specific patch releases that address these DoS vulnerabilities. Upgrade all vulnerable PgBouncer instances to the latest secure version once available. Monitor application logs and connection pooler health metrics for abnormal spikes in resource utilization or repeated crash/restart events which may indicate exploitation attempts.
