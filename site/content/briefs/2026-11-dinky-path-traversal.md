---
brief_id: brief-2026-11-08-dinky-path-traversal
event_id: brief-2026-11-08-dinky-path-traversal
revision: 1
activity_at: "2026-11-08T13:45:30Z"
title: 'DataLinkDC Dinky: Path traversal in Catalogue Upload (CVE-2026-124326)'
slug: 2026-11-dinky-path-traversal
description: DataLinkDC Dinky versions 1.2.5 and earlier contain a remote path traversal vulnerability in the catalogue upload function, for which a proof-of-concept exploit is publicly available.
date: "2026-11-08T13:45:30Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:datalinkdc:dinky:*:*:*:*:*:*:*:*
vendors:
  - DataLinkDC
products:
  - Dinky (<= 1.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument filename can lead to path traversal. The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-124326
    cvss: 5.4
    kev_status: "false"
references:
  - https://github.com/DataLinkDC/dinky/security/advisories/GHSA-2jp7-3h24-h6r7
  - https://vuldb.com/vuln/432647
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-124326
  - https://sploitus.com/exploit?id=CVE-2026-124326&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Dinky installations and assess exposure to internet-facing networks
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects public-facing catalogue upload functionality
  hunt_leads:
    - lead: Identify HTTP POST requests to catalogue upload endpoints containing path traversal characters
      technique_id: T1190
      data_needed:
        - Web server access logs
        - WAF request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs in file.getOriginalFilename of CatalogueController.java
  mitigation_plan:
    - priority: immediate
      action: Apply patch provided by DataLinkDC as referenced in GHSA-2jp7-3h24-h6r7
      owner: IT Operations
      addresses: CVE-2026-124326
      evidence: Official GHSA guidance
---

A remote path traversal vulnerability exists in DataLinkDC Dinky (up to version 1.2.5) within the `CatalogueController.java` component. The `file.getOriginalFilename` function fails to properly validate the `filename` argument during catalogue upload, allowing an attacker to perform unauthorized file operations on the host system. A proof-of-concept exploit has been published publicly.

## Impact

Successful exploitation allows a remote attacker with low-level privileges to manipulate file paths, potentially resulting in unauthorized file creation or overwriting on the host server.

## Recommendation

- Identify all instances of DataLinkDC Dinky in your environment.
- Review the official GitHub repository for patches or updates to address the vulnerability documented in GHSA-2jp7-3h24-h6r7.
- Implement strict ingress filtering and input validation for all upload endpoints, specifically monitoring requests to `CatalogueController.java` for path traversal sequences like `../` or encoded equivalents.
