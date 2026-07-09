---
title: YesWiki Unauthenticated ActivityPub Signature-Verification Bypass (CVE-2026-52767)
slug: 2026-07-yeswiki-signature-bypass
description: A critical vulnerability, CVE-2026-52767, in YesWiki's `HttpSignatureService::verifySignature()` allows unauthenticated attackers to bypass ActivityPub signature verification due to a loose boolean negation (`!openssl_verify(...)`) accepting `int(-1)` from PHP's `openssl_verify()` under specific conditions, enabling arbitrary Create, Update, and Delete operations on ActivityPub-enabled forms leading to defacement and content manipulation.
date: "2026-07-09T21:03:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - php
  - activitypub
  - signature-bypass
  - cve
  - unauthenticated-access
vendors:
  - YesWiki
products:
  - composer/yeswiki/yeswiki (>= 4.6.2, < 4.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A single unauthenticated POST per operation. No session, no CSRF, no real signature.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: Defacement / content injection at scale - a public-facing wiki with the Agenda or Blog-actu form federated becomes a publishing target for any attacker who can route TCP to the YesWiki host.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Erasure of legitimate federated content - any entry previously created via ActivityPub can be enumerated through the public outbox endpoint, its object.id discovered, and then deleted by replaying the chain with type=Delete.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mv28-wj57-f57g
rules:
  - title: Detect Unauthenticated YesWiki ActivityPub Inbox Access
    description: Detects CVE-2026-52767 exploitation - Unauthenticated POST requests to YesWiki's ActivityPub inbox endpoint, indicating potential signature bypass attempts or malicious activity. This serves as a general indicator for the attack chain.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability (CVE-2026-52767) has been identified in YesWiki versions 4.6.2 through 4.6.5, specifically within the `HttpSignatureService::verifySignature()` method. The flaw stems from a loose boolean negation check (`!openssl_verify(...)`) that incorrectly interprets a `-1` return value from PHP's `openssl_verify()` function as a successful verification. This bypass is triggered when specific conditions are met, such as using a DSA or EC public key with an RSA-only algorithm (e.g., "RSA-SHA256") on PHP 8.3 with OpenSSL 3.x. An attacker can leverage this to perform unauthenticated Create, Update, and Delete (CRUD) operations on any ActivityPub-enabled YesWiki form. This vulnerability allows for malicious content injection, defacement, spam, SEO poisoning, and data manipulation, posing a significant risk to the integrity and reputation of affected YesWiki instances.

## Attack Chain

1. An attacker establishes a public web server to host a malicious ActivityPub actor document containing a DSA public key.
2. The attacker crafts a `Create`, `Update`, or `Delete` ActivityPub request targeting the YesWiki instance's `POST /api/forms/{enabled-form-id}/actor/inbox` endpoint.
3. The malicious request includes a `Signature` header specifying `algorithm="RSA-SHA256"` and points to the attacker-controlled actor document via the `keyId` parameter.
4. YesWiki's `HttpSignatureService::verifySignature()` fetches the attacker's actor document and attempts to verify the signature using PHP's `openssl_verify()` with the DSA public key and the "RSA-SHA256" algorithm.
5. Due to the incompatibility between the DSA key and the specified "RSA-SHA256" algorithm on PHP 8.3 + OpenSSL 3.x, `openssl_verify()` returns `int(-1)`.
6. YesWiki's application logic then processes `!openssl_verify(...)`, which evaluates to `false` because `!(-1)` is `false` in PHP's truthiness rules, effectively bypassing the signature verification check.
7. The attacker easily satisfies the `Digest` header enforcement by calculating a SHA-256 hash of their malicious payload.
8. YesWiki proceeds to execute the `processActivity()` method, leading to unauthorized `Create`, `Update`, or `Delete` operations on the targeted ActivityPub-enabled forms.

## Impact

The successful exploitation of CVE-2026-52767 allows for unauthenticated CRUD operations on bazar entries of any ActivityPub-enabled YesWiki form. This can result in widespread defacement and content injection across public-facing wikis, including potential spam and SEO poisoning through manipulated entry bodies which are HTML-rendered and indexed by search engines. Attackers can also erase legitimate federated content by discovering `object.id` values via public outbox endpoints and then issuing `Delete` activities. Furthermore, the vulnerability can lead to triple-store pollution in the `yeswiki_triples` table with attacker-controlled `sourceUrl` entries, which can interfere with future federation flows and degrade the wiki's overall reputation due to the appearance of receiving signed content from a remote, yet attacker-controlled, actor.

## Recommendation

* Patch YesWiki instances immediately to version 4.6.6 or higher to address CVE-2026-52767.
* Deploy the Sigma rule `Detect Unauthenticated YesWiki ActivityPub Inbox Access` to your SIEM to monitor for suspicious POST requests to the `/api/forms/*/actor/inbox` endpoint, which is a key part of the attack chain.
* Monitor web server logs for HTTP POST requests to the `/api/forms/{id}/actor/inbox` endpoint with `Content-Type: application/activity+json` that may indicate attempted exploitation of CVE-2026-52767.
