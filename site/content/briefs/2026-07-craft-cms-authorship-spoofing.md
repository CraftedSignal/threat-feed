---
title: Craft CMS Authorship Spoofing via Authorization Bypass (CVE-2026-50279)
slug: 2026-07-craft-cms-authorship-spoofing
description: A low-privileged authenticated user can exploit CVE-2026-50279, an authorization bypass vulnerability in Craft CMS's `entries/save-entry` endpoint, to reassign an entry's authorship to another user without proper permissions, leading to corrupted audit trails and misleading content ownership.
date: "2026-07-03T11:49:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorship-spoofing
  - authorization-bypass
  - web-application
  - craft-cms
  - cve
vendors:
  - Craft CMS
products:
  - Craft CMS (5.0.0-RC1 to 5.9.20)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a low-privileged user can reassign an entry’s authorship to another user without holding the dedicated peer-author-change permission.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Defacement
    evidence: This allows low-privileged users to falsify content ownership and alter the authorship of entries
    confidence_band: high
cves:
  - id: CVE-2026-50279
    epss: 0.00245
references:
  - https://github.com/advisories/GHSA-qq2c-2q8j-jh27
---

CVE-2026-50279 details an authorization bypass vulnerability in Craft CMS versions prior to 5.9.21. Specifically, the `EntriesController::actionSaveEntry()` function performs crucial entry-edit permission checks *before* any attacker-supplied author changes are applied to the entry model. Due to this pre-mutation authorization check, a low-privileged user who is authenticated, has permission to edit an entry, and is listed as one of its existing authors (or satisfies `canChangeAuthor()` through peer entry permissions) can submit a request with crafted `authors` or `author` parameters. The controller then fails to re-run authorization after the author list has been mutated, allowing the unauthorized change to persist. This vulnerability allows falsification of content ownership, corrupting audit trails, sending misleading notifications, and breaking approval workflows within the CMS.

## Attack Chain

1.  A low-privileged authenticated user crafts an HTTP POST request targeting the `/entries/save-entry` endpoint of a vulnerable Craft CMS instance.
2.  The request includes parameters (`authors` or `author`) attempting to change the entry's author to a different user, for which the attacker does not hold explicit author-management permission.
3.  The `actionSaveEntry()` function in `EntriesController.php` loads the target entry and performs initial edit permission checks based on the *original* entry state and the attacker's existing permissions (e.g., being an existing author of the entry).
4.  The `_populateEntryModel()` helper function then processes the request, updating the entry model's `authorIds` attribute with the attacker-supplied values, critically *before* authorization for this specific author change is re-evaluated.
5.  The `canChangeAuthor()` method is invoked and returns `true` because it evaluates against the old authorship state, where the current user is still considered one of the existing authors or meets other conditions like `viewPeerEntries` for the section.
6.  The entry's author list is internally mutated within the model with the new, unauthorized `authorIds` provided by the attacker.
7.  The controller proceeds without re-running comprehensive authorization checks on the *new* author assignment, assuming the initial check was sufficient.
8.  The `saveElement()` and `_saveAuthors()` methods persist the altered author relationship to the database, resulting in the entry now appearing authored by the user specified by the attacker, effectively spoofing content ownership and compromising data integrity.

## Impact

The successful exploitation of CVE-2026-50279 allows low-privileged users to falsify content ownership and alter the authorship of entries without possessing the dedicated author-management permission. This leads to several critical impacts including corrupted audit trails, where the true historical author of content is obscured, misleading notifications being sent to incorrect users, broken approval workflows as content changes may bypass designated reviewers, and unauthorized reassignment of content responsibility. This can severely undermine trust in the CMS content and its operational processes.

## Recommendation

*   Patch CVE-2026-50279 immediately by updating all Craft CMS installations to version 5.9.21 or later.
*   Review application logs for the vulnerable `/entries/save-entry` (identified in IOCs) endpoint for unusual POST requests originating from low-privileged user accounts, especially those containing `authors` or `author` parameters, and investigate any successful changes in content ownership.
