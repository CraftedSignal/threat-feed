---
brief_id: brief-2026-11-13-fleet-vulnerabilities
event_id: brief-2026-11-13-fleet-vulnerabilities
revision: 3
activity_at: "2026-11-19T17:20:31Z"
revision_history:
  - revision: 2
    at: "2026-11-19T17:02:22Z"
    checksum: sha256:99c76613e6e4daa0bfeb266097eca7a893a238a91201c435a48ab5e0e269f4d5
    summary: added coverage for Fleet
    changed_fields:
      - action_plan
      - lastmod
      - references
      - severity
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4666
  - revision: 3
    at: "2026-11-19T17:20:31Z"
    checksum: sha256:e0da9ce57c93a6aa60e02906e405d64c867c53706066a0af16614a48219ee91f
    summary: added CVE-2026-130758;
    changed_fields:
      - affected_products
      - cpes
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-130758
title: 'Fleet: Multiple vulnerabilities'
slug: 2026-11-fleet-vulnerabilities
description: Fleet contains multiple vulnerabilities that enable a remote, authenticated attacker to perform a denial-of-service attack or escalate privileges to administrator.
date: "2026-11-13T17:51:42Z"
lastmod: "2026-11-19T17:19:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Awaiting vendor release notes for specific CVE IDs and patch version details.
cpes:
  - cpe:2.3:a:fleet:fleet:*:*:*:*:*:*:*:*
vendors:
  - Fleet
products:
  - Fleet
product_versions:
  - product: Fleet
    range: < 4.92.0
cve_verification:
  CVE-2026-130758:
    status: verified
    source: nvd
    checked_at: 2026-11-19T17:19:35.121617452Z
cves:
  - id: CVE-2026-130758
    cvss: 7.2
    epss: 0.0049
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4559
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4666
  - https://nvd.nist.gov/vuln/detail/CVE-2026-130758
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Security Operations
  immediate_actions:
    - action: Inventory all Fleet installations in the environment.
      owner: IT Operations
      due: 24h
      evidence: Source identifies Fleet as the affected product.
    - action: Inventory all deployed Fleet instances.
      owner: IT Operations
      due: 48h
      evidence: Source warning regarding multiple vulnerabilities in Fleet.
  enrichment_needed:
    - item: CVE identifiers and affected version ranges
      owner: CTI
      reason: The source lacks technical details needed to scope exposure and prioritize patching.
      evidence: Source only lists product and general vulnerability categories.
  hunt_leads:
    - lead: Monitor administrative audit logs for unusual privilege elevation events or unauthorized account modifications within the Fleet management interface.
      data_needed:
        - Fleet application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states vulnerabilities allow an authenticated attacker to gain administrator rights.
    - lead: Monitor for anomalous service instability, frequent restarts, or service crashes of the Fleet application process.
      data_needed:
        - System service logs
        - Fleet process logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states vulnerabilities allow a denial-of-service attack.
    - lead: Investigate administrative account activity for unauthorized changes or creation of new administrative accounts.
      data_needed:
        - Fleet application audit logs
        - Authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory mentions the potential for privilege escalation to administrator level.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor security updates as soon as they become available.
      owner: IT Operations
      addresses: Fleet
      evidence: Standard remediation for product-specific vulnerabilities.
  gaps:
    - Lack of specific exploit details or CVE identifiers from the primary source.
updates:
  - at: "2026-11-19T17:00:47Z"
    level: L2
    summary: added coverage for Fleet
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4666
  - at: "2026-11-19T17:19:35Z"
    level: L2
    summary: added CVE-2026-130758;
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-130758
---

## Overview

Fleet contains multiple vulnerabilities that can be exploited by a remote, authenticated attacker. Successful exploitation allows the attacker to elevate their privileges to administrator or trigger a denial-of-service condition within the application. 

## Impact

Attackers can achieve unauthorized administrative access to the Fleet environment or disrupt service availability through a denial-of-service attack.

## Recommendation

Inventory all deployments of Fleet and monitor the official vendor advisories for specific patch releases and remediation guidance. Once patches are available, prioritize upgrading all Fleet instances to the versions containing the fixes.
