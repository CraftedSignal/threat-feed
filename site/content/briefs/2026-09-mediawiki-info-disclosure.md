---
title: MediaWiki RESTBase Information Disclosure Vulnerability
slug: 2026-09-mediawiki-info-disclosure
description: MediaWiki is susceptible to an information disclosure flaw where the RESTBase-compatible API exposes the numeric user ID of hidden revision authors, allowing unauthenticated attackers to map IDs to usernames.
date: "2026-09-30T16:32:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - mediawiki
  - vulnerability
vendors:
  - Wikimedia Foundation
products:
  - MediaWiki
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An unauthenticated caller could correlate a deliberately hidden revision author with the author's account.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=76AA3B28-36A3-5900-923F-496E75CF8DC0
  - https://phabricator.wikimedia.org/T434521
  - https://bombobombone.github.io/posts/cve-2026-102971/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review MediaWiki REST API access logs for high-frequency requests combining revision lookups and user profile lookups.
      owner: SOC
      due: 48h
      evidence: The disclosure requires a revision whose author field is hidden and a wiki exposing the core REST revision route.
  mitigation_plan:
    - priority: immediate
      action: Apply the patch tracked in Phabricator task T434521 to all MediaWiki instances.
      owner: IT Operations
      addresses: CVE-2026-102971
      evidence: Public Phabricator report and fix tracking
---

A vulnerability in MediaWiki's RESTBase-compatible revision response allows for the unauthenticated disclosure of numeric user IDs associated with hidden revision authors. While the `user_text` field is correctly set to `null` and the author is marked as hidden in the API response, the underlying numeric user ID remains exposed. This ID can be cross-referenced against the public MediaWiki user lookup API to de-anonymize the author of a hidden revision. The vulnerability affects instances where the core REST revision route is exposed and the RESTBase-compatible response format is utilized. The issue was disclosed by researcher Marco Paciaroni (BomboBombone) and tracked in the MediaWiki Phabricator system under task T434521. Defenders should assess exposure of their REST API endpoints and verify patch status for affected MediaWiki versions.

## Impact

The vulnerability allows an unauthenticated actor to bypass privacy controls intended to hide revision history. By mapping the leaked numeric user ID to a public username, attackers can de-anonymize contributors who have requested privacy via the 'suppressrevision' feature. This impacts organizations relying on MediaWiki for internal or public documentation where author attribution requires strict privacy controls.

## Recommendation

* Monitor web access logs for unusual patterns of sequential requests to MediaWiki REST revision endpoints and subsequent requests to user lookup APIs.
* Audit MediaWiki configurations to restrict access to the REST revision route if it is not required for public-facing operations.
* Apply the vendor-provided patch associated with Phabricator task T434521 immediately.
