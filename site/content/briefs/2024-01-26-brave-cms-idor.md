---
title: Brave CMS Insecure Direct Object Reference Vulnerability (CVE-2026-35183)
slug: 2024-01-26-brave-cms-idor
description: Brave CMS versions prior to 2.0.6 are vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability allowing authenticated users with edit permissions to delete images attached to articles owned by other users due to missing ownership verification in the deleteImage method.
date: "2026-04-06T20:16:26Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

Brave CMS, an open-source content management system, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability in versions prior to 2.0.6. The vulnerability resides within the `deleteImage` method in `app/Http/Controllers/Dashboard/ArticleController.php`. This flaw allows an authenticated user with edit permissions, regardless of article ownership, to delete images associated with other users' articles. The root cause is the lack of proper ownership validation when processing image deletion requests. An attacker can exploit this vulnerability by crafting requests with the filenames of images belonging to other users' articles, leading to unauthorized image deletion and potential data integrity issues. This issue was resolved in version 2.0.6 of Brave CMS.

## Attack Chain

1.  Attacker authenticates to the Brave CMS application with an account that has edit permissions.
2.  Attacker identifies the filename of an image attached to an article that they do not own. This can be achieved through inspecting the HTML source code of the article page or by querying the database directly (if accessible).
3.  Attacker crafts a malicious HTTP request targeting the `deleteImage` endpoint (`app/Http/Controllers/Dashboard/ArticleController.php`).
4.  The malicious request includes the filename of the target image in the URL parameters.
5.  The `deleteImage` method processes the request without verifying if the authenticated user owns the article to which the image is attached.
6.  The application deletes the specified image file from the server's file system.
7.  The link to the deleted image in the target article is broken.
8.  The victim user, who owns the article, notices the missing image.

## Impact

Successful exploitation of this IDOR vulnerability in Brave CMS versions prior to 2.0.6 allows attackers with edit permissions to arbitrarily delete images from articles they do not own. This can lead to data integrity issues, content manipulation, and potential denial of service by removing important visual elements from the website. The impact is limited to users with edit permissions within the CMS, but can affect any article and its associated media. The CVSS v3.1 base score for this vulnerability is 7.1.

## Recommendation

*   Upgrade Brave CMS to version 2.0.6 or later to patch the CVE-2026-35183 vulnerability.
*   Implement the Sigma rule `Detect Brave CMS Image Deletion Attempt` to detect unauthorized image deletion attempts by monitoring HTTP requests to the `deleteImage` endpoint.
*   Review and harden access control policies within the Brave CMS application to ensure proper ownership validation for sensitive operations, such as image deletion.
