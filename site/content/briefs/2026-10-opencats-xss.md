---
brief_id: brief-2026-10-22-opencats-xss
event_id: brief-2026-10-22-opencats-xss
revision: 1
activity_at: "2026-10-22T18:15:20Z"
title: 'OpenCATS: Stored cross-site scripting (CVE-2026-115513)'
slug: 2026-10-opencats-xss
description: OpenCATS versions prior to 0.12.0 are vulnerable to a stored cross-site scripting flaw that allows authenticated users to execute arbitrary JavaScript in the sessions of other users, including administrators.
date: "2026-10-22T18:15:20Z"
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
  validation_status: Verified against NVD source
cpes:
  - cpe:2.3:a:opencats:opencats:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - privilege-escalation
vendors:
  - OpenCATS
products:
  - OpenCATS (< 0.12.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can exploit this by crafting a malicious record name that executes arbitrary JavaScript in the session of any other user... enabling session/cookie theft and privilege escalation to full administrative control.
    confidence_band: high
cves:
  - id: CVE-2026-115513
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115513
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenCATS to version 0.12.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source states OpenCATS before 0.12.0 contains the vulnerability
  hunt_leads:
    - lead: Search application databases for entries in candidate, company, or job order tables containing <script> tags or common XSS payloads
      technique_id: T1190
      data_needed:
        - Application database logs
        - Web server request logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Stored XSS vulnerability in specific input fields
  mitigation_plan:
    - priority: immediate
      action: Patch OpenCATS to version 0.12.0
      owner: IT Operations
      addresses: CVE-2026-115513
      evidence: Fixed version announced in advisory
---

OpenCATS versions prior to 0.12.0 contain a stored cross-site scripting (XSS) vulnerability. An authenticated low-privileged user can inject malicious HTML or JavaScript payloads into fields such as Candidate, Company, Contact, Job Order, or List names. These payloads are stored unsanitized and rendered unescaped by the lib/MRU.php script within the 'Recent' (MRU) navigation panel. Any user, including a Site Administrator, viewing the navigation panel will execute the injected script.

## Impact

Successful exploitation allows for session hijacking, cookie theft, and privilege escalation by executing arbitrary JavaScript in the context of other users. Administrative accounts are susceptible to full compromise if they interact with the injected records.

## Recommendation

* Upgrade to OpenCATS version 0.12.0 or later immediately to apply the sanitization fixes.
* Audit application logs for suspicious entries in Candidate, Company, Contact, or Job Order names that contain script tags or HTML attributes.
* Monitor administrative user sessions for unusual browser activity or rapid privilege changes.
