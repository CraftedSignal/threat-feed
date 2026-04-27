---
title: Brave CMS Insecure Direct Object Reference Vulnerability (CVE-2026-35183)
slug: 2024-01-26-brave-cms-idor
description: Brave CMS versions prior to 2.0.6 are vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability allowing authenticated users with edit permissions to delete images attached to articles owned by other users due to missing ownership verification in the deleteImage method.
date: "2026-04-06T20:16:26Z"
severities:
  - medium
tags:
  - idor
  - brave-cms
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35183
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35183
rules:
  - title: Detect Brave CMS Image Deletion Attempt
    description: Detects attempts to delete images in Brave CMS through the deleteImage endpoint, which is vulnerable to IDOR.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 1
---

Brave CMS, an open-source content management system, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability in versions prior to 2.0.6. The vulnerability resides within the `deleteImage` method in `app/Http/Controllers/Dashboard/ArticleController.php`. This flaw allows an authenticated user with edit permissions, regardless of article ownership, to delete images associated with other users' articles. The root cause is the lack of proper ownership validation when processing…
