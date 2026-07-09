---
title: YesWiki Unauthenticated Arbitrary Page Deletion (CVE-2026-52766)
slug: 2026-07-yeswiki-unauth-page-delete
description: YesWiki versions prior to 4.6.6 are vulnerable to unauthenticated arbitrary page deletion (CVE-2026-52766) via the `{{erasespamedcomments}}` wiki action, allowing any unauthenticated user to permanently delete arbitrary wiki pages, including critical ones, by sending a crafted POST request.
date: "2026-07-09T21:01:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - rce
  - data-destruction
  - cve
  - yeswiki
vendors:
  - YesWiki
products:
  - yeswiki/yeswiki (< 4.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: YesWiki vulnerable to unauthenticated arbitrary page deletion via `{{erasespamedcomments}}` action. Any user who has page write access, which is the default for everyone (`default_write_acl='*'`) on a fresh install can permanently delete arbitrary wiki pages.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: permanently delete arbitrary wiki pages, including the front page, admin pages, and pages owned by other users...issues an unconditional DELETE against `pages`, `links`, `acls`, `triples`, `referrers`, and `tags` tables.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6x7x-gcmf-7r8x
rules:
  - title: Detect YesWiki CVE-2026-52766 Trigger Page Creation
    description: Detects the creation of a YesWiki page containing the `{{erasespamedcomments}}` action, a precursor to arbitrary page deletion via CVE-2026-52766. This uses POST body content reflected in cs-uri-query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect YesWiki CVE-2026-52766 Arbitrary Page Deletion
    description: Detects exploitation of CVE-2026-52766 - an unauthenticated HTTP POST request to a YesWiki page containing `clean=yes` and `suppr[]` parameters, indicating an attempt to arbitrarily delete wiki pages.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-52766, has been identified in YesWiki versions prior to 4.6.6, enabling unauthenticated arbitrary page deletion. The flaw resides within the `{{erasespamedcomments}}` wiki action, specifically `actions/EraseSpamedCommentsAction.php`, which processes `suppr[]` parameters from a POST request without any authorization checks. This is exacerbated by YesWiki's default permissive action ACL model, where `default_write_acl='*'` allows any user, including unauthenticated ones, to trigger page creation. Furthermore, the `PageManager::deleteOrphaned()` function, despite its name, unconditionally deletes any specified page without validating its orphaned status or user permissions. This combination allows attackers to craft HTTP requests to delete any wiki page, including critical administrative pages or the front page, leading to significant data loss and service disruption. Defenders must patch immediately to prevent unauthorized content removal.

## Attack Chain

1. Attacker identifies a vulnerable YesWiki instance (version < 4.6.6) with default `default_write_acl='*'`.
2. Attacker crafts and sends an HTTP POST request to create a new wiki page, for example, to `/wiki=SpamCleanup/edit`.
3. The POST request body contains the malicious string `body={{erasespamedcomments}}`, embedding the vulnerable action.
4. YesWiki, due to the permissive `default_write_acl`, processes and creates the trigger page containing the `erasespamedcomments` action without authentication.
5. Attacker then crafts a second HTTP POST request targeting the newly created trigger page, for example, to `/wiki=SpamCleanup`.
6. This request includes `clean=yes` and a `suppr[]` array in the body, specifying the `tag` of the arbitrary target pages to be deleted (e.g., `PagePrincipale`, `AnotherTargetPage`).
7. The `actions/EraseSpamedCommentsAction.php` processes the request, invoking `PageController::delete()` and `PageManager::deleteOrphaned()`.
8. YesWiki, lacking authorization checks in the action and an unconditional delete function, permanently removes the specified wiki pages, their links, ACLs, and related data from the database.

## Impact

Successful exploitation of CVE-2026-52766 allows an unauthenticated attacker to perform arbitrary page deletion, including critical system pages like the front page (`PagePrincipale`), user-created content, or administrative sections. This leads to severe data loss, defacement, and disruption of the wiki service. The impact can range from temporary unavailability due to critical page deletion to permanent loss of valuable information, depending on backup strategies and the targeted content. Given the unauthenticated nature, mass deletion across entire wiki installations is possible.

## Recommendation

* Immediately patch YesWiki installations to version 4.6.6 or higher to remediate CVE-2026-52766.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts.
* Review web server access logs for HTTP POST requests matching the patterns in the provided Sigma rules.
* Implement strong access controls for web applications, including disabling unnecessary public write access and enforcing authentication for sensitive actions.
