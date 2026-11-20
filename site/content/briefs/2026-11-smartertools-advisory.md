---
brief_id: brief-2026-11-18-smartertools-advisory
event_id: brief-2026-11-18-smartertools-advisory
revision: 2
activity_at: "2026-11-20T03:21:53Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:21:53Z"
    checksum: sha256:4aaae67add7c5bde7ffd5abfbd5c496f839fcd0cfb6b474262822addc5a0279c
    summary: poc_available; added CVE-2026-126967
    changed_fields:
      - cpes
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=B3E18583-64C9-5D70-A0D7-95E4CB102771&utm_source=rss&utm_medium=rss
title: SmarterTools SmarterMail Security Advisory
slug: 2026-11-smartertools-advisory
description: SmarterTools has released a security update for SmarterMail versions prior to Build 9817 to remediate undisclosed vulnerabilities.
date: "2026-11-18T22:24:23Z"
lastmod: "2026-11-20T03:21:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
qa_status:
  verdict: pass
  validation_status: All facts extracted directly from CCCS advisory.
cpes:
  - cpe:2.3:a:smartertools:smartermail:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B3E18583-64C9-5D70-A0D7-95E4CB102771&utm_source=rss&utm_medium=rss
vendors:
  - SmarterTools
products:
  - SmarterMail (< Build 9817)
cve_verification:
  CVE-2026-126967:
    status: verified
    source: nvd
    checked_at: 2026-11-20T03:21:28.380139864Z
cves:
  - id: CVE-2026-126967
    cvss: 8.8
    epss: 0.01813
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/smartertools-security-advisory-av26-1177
  - https://www.smartertools.com/smartermail/release-notes/current
  - https://www.smartertools.com/smartermail/downloads
  - https://sploitus.com/exploit?id=B3E18583-64C9-5D70-A0D7-95E4CB102771&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory all SmarterMail installations and upgrade to build 9817.
      owner: IT Operations
      due: 48h
      evidence: SmarterTools security advisory AV26-1177
  mitigation_plan:
    - priority: immediate
      action: Upgrade SmarterMail to build 9817 or later.
      owner: IT Operations
      addresses: Undisclosed vulnerabilities in SmarterMail
      evidence: CCCS advisory AV26-1177
updates:
  - at: "2026-11-20T03:21:28Z"
    level: L2
    summary: poc_available; added CVE-2026-126967
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=B3E18583-64C9-5D70-A0D7-95E4CB102771&utm_source=rss&utm_medium=rss
---

## Overview

On November 18, 2026, the Canadian Centre for Cyber Security released an advisory (AV26-1177) regarding undisclosed vulnerabilities affecting SmarterMail. The vulnerability impacts all SmarterMail builds prior to 9817. The vendor has provided release notes and download links for the update.

## Recommendation

Inventory all deployments of SmarterMail within the organization. Upgrade all instances of SmarterMail to build 9817 or later immediately. Monitor the SmarterTools official release notes for further technical details regarding the patched vulnerabilities as they become available.
