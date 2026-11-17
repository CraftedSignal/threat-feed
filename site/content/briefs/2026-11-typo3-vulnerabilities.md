---
brief_id: brief-2026-11-17-typo3-vulnerabilities
event_id: brief-2026-11-17-typo3-vulnerabilities
revision: 1
activity_at: "2026-11-17T15:16:15Z"
title: 'TYPO3 CMS: Multiple Remote Code Execution and Data Access Vulnerabilities'
slug: 2026-11-typo3-vulnerabilities
description: Multiple vulnerabilities in TYPO3 CMS (versions 10-14) allow for remote code execution, cross-site scripting, and unauthorized information disclosure, with some flaws already seeing active exploitation.
date: "2026-11-17T15:16:15Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
cpes:
  - cpe:2.3:a:typo3:cms:*:*:*:*:*:*:*:*
tags:
  - rce
  - xss
  - cve
  - typo3
vendors:
  - TYPO3
products:
  - TYPO3 CMS (10.x < 10.4.63)
  - TYPO3 CMS (11.x < 11.5.57)
  - TYPO3 CMS (12.x < 12.4.52)
  - TYPO3 CMS (13.x < 13.4.40)
  - TYPO3 CMS (14.x < 14.3.12)
cves:
  - id: CVE-2026-119621
    kev_status: unknown
  - id: CVE-2026-119622
    kev_status: "false"
  - id: CVE-2026-119623
    kev_status: "false"
  - id: CVE-2026-125159
    kev_status: "false"
  - id: CVE-2026-125160
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1553/
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-2prm-vj76-hv7x
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-3x7g-4rhf-5r97
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-46vm-rxq7-5q87
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-7hg6-f5v4-8h7x
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-98gj-8653-gqjx
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-9m29-4wg9-8v93
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-9vwr-83hh-5qwf
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-cg52-w7qf-xvv9
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-rh78-wcww-vqm5
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-xc46-q68g-r6h6
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all TYPO3 CMS installations to the identified fixed versions (10.4.63, 11.5.57, 12.4.52, 13.4.40, or 14.3.12).
      owner: IT Operations
      due: 24h
      evidence: Vendor security bulletins confirm these versions address the listed CVEs.
  hunt_leads:
    - lead: Search web server logs for suspicious file creation attempts in the public web root, specifically targeting filenames starting with FIRST_INSTALL or ending in unexpected extensions like .php or .html after image/form uploads.
      data_needed:
        - webserver access logs
        - file integrity monitoring alerts
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-119623 and CVE-2026-119622 document creation of files in the web root as part of the exploitation path.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-recommended patches to address CVE-2026-119621, CVE-2026-119622, CVE-2026-119623, CVE-2026-125159, and CVE-2026-125160.
      owner: IT Operations
      addresses: Multiple CVEs
      evidence: Vendor security advisories.
---

## Overview
Multiple vulnerabilities have been disclosed in the TYPO3 content management system. These flaws range from remote code execution to information disclosure, affecting versions 10.x through 14.x. At least one vulnerability (CVE-2026-125160) is known to be actively exploited in the wild.

## Vulnerabilities
- CVE-2026-119621: Remote code execution in the Import/Export module via arbitrary file write using crafted T3D/XML files.
- CVE-2026-119622: Backend file write vulnerability via the online media endpoint, potentially leading to RCE in combination with other flaws.
- CVE-2026-119623: Re-enabling the installation wizard on already configured instances by placing marker files in the public web root.
- CVE-2026-125159: Information disclosure via ImageMagick/GraphicsMagick MVG coders when processing crafted image uploads.
- CVE-2026-125160: Exposure of temporary file paths leading to cross-site scripting (XSS) in the Form Framework. This vulnerability is reported as actively exploited.

## Recommendation
- Audit all TYPO3 instances and upgrade to the latest patched versions immediately: 10.4.63, 11.5.57, 12.4.52, 13.4.40, or 14.3.12.
- Review TYPO3 access logs and web server error logs for unexpected file creations in the public web root or attempts to reach installation-related endpoints.
- Ensure appropriate Content-Security-Policy (CSP) is implemented to mitigate XSS risks related to form uploads.
