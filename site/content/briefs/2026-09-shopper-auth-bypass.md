---
title: Authorization Bypass in Shopper Framework CollectionProducts Component
slug: 2026-09-shopper-auth-bypass
description: An authorization bypass vulnerability in the Shopper framework allows authenticated users with limited privileges to perform unauthorized product deletions across any collection in the database.
date: "2026-09-12T00:57:35Z"
lastmod: "2026-09-12T00:57:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:shopper:framework:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - auth-bypass
  - web-vulnerability
  - authorization-bypass
  - shopper
  - cve-2026-56828
  - cms
vendors:
  - Shopper
products:
  - shopper/framework (< 2.9.2)
  - shopper/framework (>= 2.8.0, < 2.9.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1565.002
    technique_name: Data Manipulation
    evidence: An authenticated user with only browse privileges can manipulate the collection ID to detach products from any collection in the database.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The combination of missing authorization and an unlocked model binding lets the attacker both bypass the permission gate and redirect the mutation to an arbitrary variant in the database.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2cg9-97gq-9mqp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56825
  - https://github.com/advisories/GHSA-g3f9-g5vj-p62f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56829
  - https://github.com/advisories/GHSA-j328-xmgp-j4q3
  - https://github.com/shopperlabs/shopper/commit/fcd0c5920588702df5b874f432b1042abd77a50b
  - https://github.com/advisories/GHSA-243p-f3cv-c5wh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56827
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade shopper/framework to 2.9.2 or later
      owner: IT Operations
      due: 24h
      evidence: Source provides fixed version 2.9.2
  hunt_leads:
    - lead: Analyze web logs for POST requests to /shopper/livewire/update containing callBulkAction methods
      technique_id: T1565.002
      data_needed:
        - Web server access logs or WAF logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Proof of concept demonstrates the use of callBulkAction via /shopper/livewire/update
  mitigation_plan:
    - priority: immediate
      action: Upgrade shopper/framework to 2.9.2
      owner: IT Operations
      addresses: CVE-2026-56825
      evidence: Fixed version provided in advisory
updates:
  - at: "2026-09-12T00:57:44Z"
    level: L2
    summary: added coverage for shopper/framework (< 2.9.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-g3f9-g5vj-p62f
  - at: "2026-09-12T00:57:52Z"
    level: L2
    summary: added coverage for shopper/framework (>= 2.8.0, < 2.9.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-j328-xmgp-j4q3
  - at: "2026-09-12T00:57:58Z"
    level: L2
    summary: added coverage for shopper/framework (< 2.9.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-243p-f3cv-c5wh
---

Shopper framework versions prior to 2.9.2 are vulnerable to an authorization bypass in the `CollectionProducts` Livewire component. The vulnerability stems from two primary issues: the `collection` property is not locked, allowing arbitrary modification of the collection ID by the client, and the delete and bulk-delete actions lack proper authorization checks. An authenticated user possessing only the `browse_collections` role can manipulate Livewire network payloads to target and empty any collection within the store's database. This vulnerability effectively escalates a user's privileges, allowing them to perform destructive actions against storefront catalog groupings and promotions without the necessary `edit_collections` permissions. This impacts organizations relying on Shopper for e-commerce catalog management, as an attacker can systematically detach products from collections, disrupting site functionality and promotional campaigns.

## Attack Chain

1. Attacker authenticates to the admin panel using valid, low-privileged credentials (e.g., `browse_collections` only).
2. Attacker inspects the `CollectionProducts` Livewire component to identify the target collection ID and the component snapshot structure.
3. Attacker captures the XSRF token and active session cookie to prepare the authenticated network request.
4. Attacker constructs a malicious POST request targeting the `/shopper/livewire/update` endpoint.
5. Attacker replaces the legitimate `collection` ID within the Livewire component snapshot data with an arbitrary target collection ID.
6. Attacker invokes the `callBulkAction` method within the payload, specifying the 'delete' action and a list of product IDs to detach.
7. The server processes the request without verifying the caller's authorization or validating the component state.
8. Targeted products are detached from the specified collection, resulting in a loss of catalog integrity.

## Impact

The successful exploitation of this vulnerability allows unauthorized users to detach products from any collection in the database. This causes immediate disruption to storefront catalog groupings, landing pages, and promotional activities linked to these collections. Because the attacker can target any collection ID, the scope of impact is the entire catalog database rather than just the collections associated with their assigned permissions.

## Recommendation

1. Upgrade `shopper/framework` to version 2.9.2 or later immediately to patch the missing authorization and property locking.
2. Audit administrative roles to ensure the least-privilege principle is applied and monitor for unauthorized `callBulkAction` requests in server logs.
3. Validate that all Livewire components sensitive to user input use the `#[Locked]` attribute to prevent client-side property modification.
