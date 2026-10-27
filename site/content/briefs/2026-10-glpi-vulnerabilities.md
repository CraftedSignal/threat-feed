---
brief_id: brief-2026-10-27-glpi-vulnerabilities
event_id: brief-2026-10-27-glpi-vulnerabilities
revision: 1
activity_at: "2026-10-27T17:39:00Z"
title: GLPI Multiple Vulnerabilities
slug: 2026-10-glpi-vulnerabilities
description: Multiple vulnerabilities in GLPI allow remote attackers to perform SQL injection, cross-site scripting, and security policy bypass, resulting in data integrity loss.
date: "2026-10-27T17:39:00Z"
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
  validation_status: Confirmed against ANSSI advisory and referenced GHSA documents.
tags:
  - webserver
  - sql-injection
  - xss
  - patch-management
vendors:
  - GLPI
products:
  - GLPI (< 10.0.27)
  - GLPI (11.0.x < 11.0.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une atteinte à l'intégrité des données, une injection SQL (SQLi) et une injection de code indirecte à distance (XSS).
    confidence_band: high
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1389/
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-3rr2-mxv6-rmc2
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-5jg3-2qx2-gq7g
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-753w-2942-4pxm
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-75jp-p2vm-9vmh
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-7x93-gxc8-jp8m
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-hv93-qr6v-7mpj
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-pr87-h373-xr6c
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch GLPI to version 10.0.27 or 11.0.9.
      owner: IT Operations
      due: 48h
      evidence: Source advisory identifies versions prior to 10.0.27 and 11.0.9 as affected.
  hunt_leads:
    - lead: Inspect web server logs for SQL injection patterns targeting GLPI endpoints.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source explicitly mentions SQL injection (SQLi) risk.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GLPI to latest release version.
      owner: IT Operations
      addresses: Vulnerabilities within GLPI
      evidence: Solutions section of the ANSSI advisory.
---

The French National Cybersecurity Agency (ANSSI) has released an advisory regarding multiple vulnerabilities in the GLPI software. The identified flaws permit attackers to conduct SQL injection (SQLi) attacks, execute remote cross-site scripting (XSS), bypass security policies, and manipulate data integrity. These vulnerabilities affect GLPI versions 10.0.x prior to 10.0.27 and 11.0.x prior to 11.0.9.

## Impact
Successful exploitation allows for unauthorized data manipulation, security policy circumvention, and the execution of malicious scripts in the context of user sessions.

## Recommendation
- Inventory all internal deployments of GLPI to identify affected versions.
- Apply the latest security patches provided by the GLPI project by upgrading to versions 10.0.27 or 11.0.9 or later.
- Refer to the security advisories published on the GLPI GitHub security page (GHSA-3rr2-mxv6-rmc2, GHSA-5jg3-2qx2-gq7g, GHSA-753w-2942-4pxm, GHSA-75jp-p2vm-9vmh, GHSA-7x93-gxc8-jp8m, GHSA-hv93-qr6v-7mpj, GHSA-pr87-h373-xr6c) for specific mitigation details per CVE.
