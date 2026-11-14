---
brief_id: brief-2026-11-14-ghost-rce
event_id: brief-2026-11-14-ghost-rce
revision: 1
activity_at: "2026-11-14T22:06:22Z"
title: 'Ghost CMS: Remote Code Execution via oEmbed SVG Processing and Theme Upload'
slug: 2026-11-ghost-rce
description: Ghost CMS is susceptible to two independent RCE vulnerabilities, CVE-2026-105642 and CVE-2026-105677, allowing contributors or administrators to gain command execution via malicious SVG oEmbed requests or crafted theme uploads.
date: "2026-11-14T22:06:22Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:tryghost:ghost:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=28E5AAE9-9E78-5005-80B8-066FEAC833C0&utm_source=rss&utm_medium=rss
vendors:
  - TryGhost
products:
  - Ghost
affected_os:
  - Node.js
cves:
  - id: CVE-2026-105642
    kev_status: "false"
  - id: CVE-2026-105677
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-105642
  - https://cveawg.mitre.org/api/cve/CVE-2026-105677
  - https://sploitus.com/exploit?id=28E5AAE9-9E78-5005-80B8-066FEAC833C0
  - https://sploitus.com/exploit?id=28E5AAE9-9E78-5005-80B8-066FEAC833C0&utm_source=rss&utm_medium=rss
---

## Overview
Ghost CMS is affected by two distinct remote code execution (RCE) vulnerabilities. CVE-2026-105642 is a vulnerability in the bundled image processing library's SVG handling. Any staff user, including Contributors, can create a bookmark card for an attacker-controlled website, resulting in arbitrary commands being run on the Ghost server. This issue is fixed in version 6.67.0. CVE-2026-105677 is a vulnerability in how Ghost loads theme translation files, allowing an authenticated Administrator to execute arbitrary code on the server via a crafted theme when the 'themeTranslation' labs flag is enabled. This issue is fixed in version 6.64.0.

## Attack Chain
For CVE-2026-105642, an attacker uses a Contributor account to trigger an oEmbed request for a bookmark card pointing to an attacker-controlled URL containing a crafted SVG. For CVE-2026-105677, an administrator uploads a theme containing a directory named as a locale file within the 'locales/' directory, triggering code execution during the loader's directory resolution process.

## Impact
Successful exploitation of either vulnerability results in arbitrary command execution on the host server within the context of the Ghost application.

## Recommendation
Upgrade Ghost CMS to version 6.67.0 to address CVE-2026-105642, and to 6.64.0 to address CVE-2026-105677. For CVE-2026-105677, ensure the 'themeTranslation' labs flag is disabled if not required.
