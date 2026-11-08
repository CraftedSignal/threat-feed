---
brief_id: brief-2026-11-08-openemr-xss
event_id: brief-2026-11-08-openemr-xss
revision: 1
activity_at: "2026-11-08T15:31:55Z"
title: 'OpenEMR: Stored cross-site scripting in CCDA/CCD preview (CVE-2026-124448)'
slug: 2026-11-openemr-xss
description: OpenEMR versions before 8.3.0 are vulnerable to stored cross-site scripting via maliciously crafted CCDA/CCD document attachments that execute scripts in a clinician's session upon preview.
date: "2026-11-08T15:31:55Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: No environment validation performed
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application-vulnerability
  - health-sector
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users can upload a crafted CCDA/CCD document with onmouseover, onclick, or onfocus handlers to execute script in a clinician's session when previewed.
    confidence_band: high
cves:
  - id: CVE-2026-124448
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124448
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124448 remediation
  hunt_leads:
    - lead: Monitor web access logs for anomalous uploads of CCDA/CCD document types by non-clinical users
      technique_id: T1190
      data_needed:
        - Web server access logs
        - OpenEMR application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated users can upload a crafted CCDA/CCD document
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124448
      evidence: Vulnerability remediation
---

OpenEMR versions prior to 8.3.0 contain stored cross-site scripting (XSS) vulnerabilities within the CCDA/CCD preview stylesheets. Specifically, the cda.xsl and ccd.xsl files fail to properly sanitize input, allowing event-handler attributes such as onmouseover, onclick, and onfocus to be injected into previewed HTML. An authenticated attacker can upload a crafted CCDA/CCD document containing these malicious handlers to execute unauthorized JavaScript in the context of a clinician's session.

## Impact
Successful exploitation allows authenticated attackers to execute arbitrary JavaScript within a clinician's session, potentially leading to unauthorized data access, session hijacking, or other actions performed with the clinician's privileges within the OpenEMR application.

## Recommendation
- Upgrade OpenEMR to version 8.3.0 or later to apply the fix for CVE-2026-124448.
- Implement Content Security Policy (CSP) headers that restrict inline script execution to reduce the impact of XSS vulnerabilities.
- Audit access logs for user accounts uploading CCDA/CCD documents to identify potential abuse of the file upload functionality.
