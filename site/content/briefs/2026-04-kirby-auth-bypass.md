---
title: Kirby CMS Missing Authorization Vulnerability
slug: 2026-04-kirby-auth-bypass
description: A missing authorization vulnerability in Kirby CMS allows authenticated users to bypass intended access restrictions on pages and files, potentially leading to unauthorized information disclosure and content modification; patched in versions 4.9.0 and 5.4.0.
date: "2026-04-30T21:03:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - cms
  - web-application
vendors:
  - getkirby
products:
  - cms (<= 4.8.0)
  - cms (>= 5.0.0, <= 5.3.3)
  - Kirby Panel
  - Kirby REST API
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://github.com/advisories/GHSA-85x2-r8xv-ww8c
  - https://github.com/getkirby/kirby/releases/tag/4.9.0
  - https://github.com/getkirby/kirby/releases/tag/5.4.0
  - CVE-2026-42137
rules:
  - title: Detect Kirby CMS API Access to Restricted Resources
    description: Detects attempts to access restricted resources via the Kirby CMS REST API, potentially indicating exploitation of the missing authorization vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: Detect Kirby CMS Unauthorized File Access via API
    description: Detects attempts to access files via the Kirby CMS REST API that may be unauthorized due to missing permission checks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kirby CMS versions prior to 4.9.0 and between 5.0.0 and 5.3.3 are vulnerable to a missing authorization flaw. This vulnerability impacts Kirby sites where user roles are intentionally configured with restricted access to pages or files through disabled `pages.access`, `pages.list`, `files.access`, or `files.list` permissions. The issue stems from inconsistent permission checks within the Kirby Panel and REST API, allowing authenticated users to access resources they should not be able to. Updating to versions 4.9.0, 5.4.0, or later resolves this vulnerability by implementing consistent permission checks. The vulnerability is identified as CVE-2026-42137.

## Attack Chain

1. An authenticated user logs into the Kirby CMS Panel or REST API.
2. The user attempts to access a page or file for which their role lacks the necessary `pages.access`/`files.access` or `pages.list`/`files.list` permissions.
3. Due to inconsistent permission checks, the user can view the page or file details via the "changes" dialog in the Panel, even if listing is disabled.
4. The user accesses the REST API, which, despite direct access checks, fails to properly filter collections or related models (children, drafts, files, etc.).
5. The attacker views images associated with restricted site, pages, or user resources in lists within the Panel.
6. The user exploits the incorrect permission check (using `pages.access` instead of `pages.list` or `files.access` instead of `files.list` in specific API routes).
7. The user traverses to previous or next files using direct links in the files view, even if those files should not be listable.
8. The attacker gains unauthorized access to sensitive information or modifies content due to the bypassed permission checks.

## Impact

This vulnerability allows authenticated users to bypass intended access restrictions within Kirby CMS, leading to potential unauthorized access to sensitive information and/or unauthorized content modification. The inconsistent permission checks in the Panel and REST API could result in unintended disclosure of data restricted by role-based access controls. Successful exploitation could compromise the confidentiality and integrity of the affected Kirby CMS instance. While the advisory does not list the number of victims, this flaw impacts any Kirby site with restricted roles.

## Recommendation

*   Upgrade to Kirby CMS version 4.9.0 or 5.4.0 (or later) to patch the vulnerability as recommended in the advisory.
*   Review user role permissions and blueprint configurations to ensure appropriate access controls are in place after patching, as described in the overview.
*   Monitor web server logs for unusual API requests to resources that should be restricted, using the rules below, to identify potential exploitation attempts.
*   Implement rate limiting on API endpoints to mitigate potential brute-force attacks attempting to exploit this or other vulnerabilities.
