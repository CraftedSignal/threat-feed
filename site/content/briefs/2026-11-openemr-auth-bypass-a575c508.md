---
brief_id: brief-2026-11-08-openemr-auth-bypass-a575c508
event_id: brief-2026-11-08-openemr-auth-bypass-a575c508
revision: 1
activity_at: "2026-11-08T15:34:30Z"
title: 'OpenEMR: Missing authorization in document upload (CVE-2026-124461)'
slug: 2026-11-openemr-auth-bypass-a575c508
description: OpenEMR versions prior to 8.3.0 are susceptible to an authorization bypass vulnerability allowing authenticated users to read and overwrite arbitrary document data via the library/ajax/upload.php script.
date: "2026-11-08T15:34:30Z"
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
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - authorization-bypass
  - health-sector
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
cves:
  - id: CVE-2026-124461
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124461
rules:
  - title: Detect CVE-2026-124461 Exploitation - Authorization Bypass in library/ajax/upload.php
    description: Detects potential exploitation of CVE-2026-124461 by monitoring for unauthorized document access patterns via the library/ajax/upload.php endpoint
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1020
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: OpenEMR before 8.3.0 contains a missing authorization vulnerability in library/ajax/upload.php
  hunt_leads:
    - lead: Identify authenticated users making high-frequency POST requests to library/ajax/upload.php
      data_needed:
        - webserver logs containing UserID and request volume per minute
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Low-privilege users can enumerate doc_id values with the fetch and save actions
  mitigation_plan:
    - priority: immediate
      action: Apply security patch by upgrading to OpenEMR 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124461
      evidence: OpenEMR before 8.3.0 contains a missing authorization vulnerability
---

OpenEMR versions prior to 8.3.0 contain a missing authorization vulnerability in 'library/ajax/upload.php'. This flaw permits an authenticated user to perform unauthorized read and write operations on document data by manipulating the 'doc_id' parameter.

## Impact
Successful exploitation allows low-privileged users to enumerate document IDs, leading to the unauthorized disclosure of patient health information (PHI) and the potential tampering of medical records across the entire installation.

## Recommendation
- Upgrade OpenEMR to version 8.3.0 or later to remediate the authorization logic flaw.
- Implement strict access control monitoring for requests directed to 'library/ajax/upload.php'.
- Review application access logs for abnormal volumes of requests to the document upload endpoint, specifically those targeting sequential or unusual 'doc_id' values.
