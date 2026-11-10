---
brief_id: brief-2026-11-10-dce-web-vulnerabilities
event_id: brief-2026-11-10-dce-web-vulnerabilities
revision: 1
activity_at: "2026-11-10T19:00:09Z"
title: 'Social Security Administration dce-web: Multiple Vulnerabilities (CVE-2026-104371, CVE-2026-104372, CVE-2026-104373)'
slug: 2026-11-dce-web-vulnerabilities
description: The decommissioned dce-web application contained vulnerabilities involving missing Subresource Integrity (CVE-2026-104371), supply chain risks from unpinned development dependencies (CVE-2026-104372), and internal SMB path exposure (CVE-2026-104373).
date: "2026-11-10T19:00:09Z"
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
  likelihood: unlikely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ssa:dce-web:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - supply-chain
  - information-disclosure
  - cisa
vendors:
  - Social Security Administration
products:
  - dce-web
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592.002
    technique_name: Software
    evidence: The gulp build script hardcodes the internal SSA SMB/UNC share used as the development deployment target.
    confidence_band: high
cves:
  - id: CVE-2026-104371
    kev_status: unknown
  - id: CVE-2026-104372
    kev_status: unknown
  - id: CVE-2026-104373
    kev_status: unknown
references:
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/VA/white/2026/va-26-314-01.json
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  immediate_actions:
    - action: Confirm decommissioning of the dce-web project and associated build servers.
      owner: IT Operations
      due: 7d
      evidence: 'Remediation status provided by source: The dce-web repository has been decommissioned as of 9/18/26.'
  hunt_leads:
    - lead: Search legacy source code repositories for hardcoded UNC/SMB paths or internal network infrastructure disclosures.
      technique_id: T1592.002
      data_needed:
        - Repository contents
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The gulp build script hardcodes the internal SSA SMB/UNC share used as the development deployment target.
---

The Social Security Administration (SSA) 'dce-web' application was found to contain three security vulnerabilities discovered via internal audit. While the repository was decommissioned on September 18, 2026, the findings highlight risks associated with legacy build processes and configuration.

- CVE-2026-104371: Bootstrap CSS files were loaded from a CDN without subresource integrity (SRI), enabling potential CSS injection, UI redressing, or phishing within the dashboard.
- CVE-2026-104372: The project lacked a lockfile and used outdated build dependencies (2016-2017), rendering automated software composition analysis (SCA) ineffective and exposing developer environments to known vulnerabilities like WebSocket origin check bypasses and ReDoS.
- CVE-2026-104373: Build scripts (`gulpfile.js`) contained hardcoded internal SSA SMB/UNC network paths, facilitating internal network reconnaissance.

## Recommendation

- Verify that the 'dce-web' repository and any associated build environments have been fully decommissioned as per the reported remediation date of September 18, 2026.
- Conduct a review of legacy repositories to identify and remediate hardcoded internal network paths, especially within build configurations or deployment scripts.
- Implement mandatory Subresource Integrity (SRI) for all third-party resources loaded in web applications to prevent content tampering.
- Enforce the use of lockfiles (e.g., `package-lock.json`, `yarn.lock`) in all development projects to ensure reproducible builds and allow for accurate, ongoing SCA vulnerability scanning.
