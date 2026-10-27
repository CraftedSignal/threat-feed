---
brief_id: brief-2026-10-27-nextcloud-multi-vuln
event_id: brief-2026-10-27-nextcloud-multi-vuln
revision: 2
activity_at: "2026-10-27T17:40:07Z"
revision_history:
  - revision: 2
    at: "2026-10-27T17:40:07Z"
    checksum: sha256:195a177e9f74b095b538b924fd6a66a030b8ab05571f50935f2dff852f6b043a
    summary: added coverage for Nextcloud Server +4 products
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1392/
title: 'Nextcloud: Multiple vulnerabilities in Server and plugins'
slug: 2026-10-nextcloud-multi-vuln
description: Nextcloud disclosed multiple vulnerabilities across its server platform and various applications, including Tables, Whiteboard, Files Confidential, Collectives, and Richdocuments, which could allow attackers to bypass security controls, manipulate data, or cause Denial-of-Service.
date: "2026-10-27T17:34:27Z"
lastmod: "2026-10-27T17:39:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source does not provide technical details or CVEs; action plan focuses on inventory and update management.
tags:
  - vulnerability
  - nextcloud
  - webserver
vendors:
  - Nextcloud
products:
  - Nextcloud Server
  - Nextcloud Tables
  - Nextcloud Whiteboard
  - Nextcloud Files Confidential
  - Nextcloud Collectives
  - Nextcloud Richdocuments
  - Nextcloud Server Enterprise
  - Collectives (> 4.0.0, < 4.4.0)
  - Files Confidential (3.3.x < 3.3.1, > 4.0.0 < 4.1.1, > 5.0.0 < 5.1.0)
  - Richdocuments (11.0.x < 11.0.1, > 10.0.0 < 10.2.1, > 9.0.0 < 9.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein Angreifer kann mehrere Schwachstellen in Nextcloud ausnutzen, um Sicherheitsvorkehrungen zu umgehen.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein Angreifer kann mehrere Schwachstellen in Nextcloud ausnutzen, um Denial-of-Service-Zustände auszulösen.
    confidence_band: high
cves:
  - id: CVE-2026-114601
    kev_status: unknown
  - id: CVE-2026-67400
    kev_status: unknown
  - id: CVE-2026-77167
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-77171
    cvss: 3.5
    kev_status: "false"
  - id: CVE-2026-77172
    cvss: 5.3
    kev_status: "false"
  - id: CVE-2026-77173
    cvss: 4.3
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4185
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1392/
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5572-968j-v7g5
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-6m4h-j3wr-v388
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-p9qq-6vpv-x7wj
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qwm4-h3xh-gmvc
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-w7pp-8m7c-555c
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-x4hv-m8g6-5cj4
  - https://www.cve.org/CVERecord?id=CVE-2026-114601
  - https://www.cve.org/CVERecord?id=CVE-2026-67400
  - https://www.cve.org/CVERecord?id=CVE-2026-77167
  - https://www.cve.org/CVERecord?id=CVE-2026-77171
  - https://www.cve.org/CVERecord?id=CVE-2026-77172
  - https://www.cve.org/CVERecord?id=CVE-2026-77173
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Perform inventory of all deployed Nextcloud applications and versions
      owner: IT Operations
      due: 24h
      evidence: Multiple vulnerabilities reported across server and specific apps.
    - action: Patch affected Nextcloud Server and application versions to the latest releases listed in the vendor advisories.
      owner: IT Operations
      due: 48h
      evidence: Multiple vulnerabilities discovered in Nextcloud products require patching as per vendor security advisories.
  hunt_leads:
    - lead: Monitor web server access logs for anomalous request patterns targeting /apps/ or known plugin endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-stem, sc-status, cs-method)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Potential for exploitation via public-facing components.
  mitigation_plan:
    - priority: immediate
      action: Update Nextcloud Server and affected apps to the latest security release
      owner: IT Operations
      addresses: Vulnerabilities in Nextcloud core and extensions
      evidence: Source advises addressing disclosed vulnerabilities
updates:
  - at: "2026-10-27T17:39:09Z"
    level: L2
    summary: added coverage for Nextcloud Server +4 products
    sources:
      - anssi
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1392/
---

Nextcloud has issued a security advisory regarding multiple vulnerabilities affecting the Nextcloud Server core and several official applications: Tables, Whiteboard, Files Confidential, Collectives, and Richdocuments. Successful exploitation of these issues may allow an attacker to bypass security measures, access or modify sensitive data, or impact service availability via Denial-of-Service (DoS). Specific CVE identifiers were not provided in the source material. Users are advised to review the official Nextcloud advisory portal for specific version remediation details.

## Impact
Impact includes unauthorized data disclosure, data manipulation, security control bypass, and service disruption (DoS).

## Recommendation
- Inventory all Nextcloud instances and integrated applications, specifically Tables, Whiteboard, Files Confidential, Collectives, and Richdocuments.
- Review the official Nextcloud security advisory portal to identify and apply the necessary patches for your specific versions.
- Prioritize patching of internet-facing Nextcloud instances.
