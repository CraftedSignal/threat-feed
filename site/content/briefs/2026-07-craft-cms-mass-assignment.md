---
title: Craft CMS Mass Assignment Vulnerability Allows Element Overwrites (CVE-2026-50281)
slug: 2026-07-craft-cms-mass-assignment
description: A high-severity mass assignment vulnerability (CVE-2026-50281) in Craft CMS versions prior to 5.9.21 allows a low-privileged authenticated attacker to overwrite arbitrary existing element data, such as entries or user profiles, by manipulating the `newAttributes` parameter during a bulk duplication action.
date: "2026-07-03T11:31:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - vulnerability
  - mass-assignment
  - cve
  - cms
vendors:
  - Craft CMS
products:
  - Craft CMS (>= 5.7.0, < 5.9.21)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Alice’s title, slug, authorId, postDate, and UID land on Bob’s entry.
    confidence_band: high
cves:
  - id: CVE-2026-50281
references:
  - https://github.com/advisories/GHSA-x5m4-g2cq-52pq
---

A critical mass assignment flaw (CVE-2026-50281) has been identified in Craft CMS versions 5.7.0 through 5.9.20, enabling low-privileged authenticated users to corrupt content integrity across the entire installation. This vulnerability, disclosed on July 2, 2026, stems from insufficient input validation within the `actionBulkDuplicate()` function. An attacker with basic entry duplication permissions can craft a request that includes a target element's `id` within the `newAttributes` parameter. This malicious `id` bypasses the system's intended `id = null` reset during the duplication process, leading the application to overwrite an existing element's data in the database instead of creating a new one. This flaw allows unauthorized modification of any element an attacker can predict or enumerate, significantly impacting data integrity.

## Attack Chain

1.  An authenticated attacker, possessing only the permission to duplicate an entry they own, logs into the Craft CMS administrative interface.
2.  The attacker crafts a malicious HTTP POST request to the `actionBulkDuplicate` endpoint (e.g., `/admin/actions/elements/bulk-duplicate`).
3.  This request includes two required parameters: `elements` (identifying an entry the attacker owns) and `newAttributes`.
4.  Within the `newAttributes` parameter, the attacker injects a `id` field containing the numeric primary key of an existing target element owned by another user or administrative account.
5.  The `ElementsController::actionBulkDuplicate` method processes this request, passing the `newAttributes` parameter to the service layer without performing an explicit `id` validation check for nested attributes.
6.  `Elements::duplicateElement` attempts to clone the source element and explicitly sets the new element's `id` to `null` in preparation for a new database record.
7.  Immediately afterward, `Craft::configure` applies the attacker-provided `newAttributes` array to the cloned element. Due to `id` being present in `safeAttributes()`, the attacker's `id` value overwrites the `id=null` value.
8.  The underlying database save operation (via Yii's `saveElement()`) then performs an `UPDATE` on the database row identified by the attacker-controlled `id`, effectively overwriting the target element's data with the attacker's supplied content.

## Impact

Successful exploitation of CVE-2026-50281 allows a low-privileged authenticated user to overwrite the data of any existing elements within the Craft CMS installation. This includes entries, categories, and even user accounts that share the `Entry` element table inheritance. The primary impact is a complete loss of content integrity, as an attacker can arbitrarily modify or deface content owned by other users or even administrative content. This can lead to misinformation, reputational damage, and potentially further compromise if critical information in other elements is overwritten. The attack requires only the ability to duplicate an existing entry.

## Recommendation

*   Patch CVE-2026-50281 immediately by upgrading Craft CMS to version 5.9.21 or later.
*   Review access control configurations for all users to ensure the principle of least privilege is applied, especially regarding content creation and duplication permissions.
