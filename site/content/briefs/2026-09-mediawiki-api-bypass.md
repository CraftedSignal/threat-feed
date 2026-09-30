---
title: Authorization Bypass in MediaWiki RevisionDelete API
slug: 2026-09-mediawiki-api-bypass
description: An authorization bypass vulnerability in MediaWiki's RevisionDelete API allows users with limited privileges to remove suppression bits, exposing protected content due to improper permission validation.
date: "2026-09-30T17:33:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:mediawiki:mediawiki:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - authorization-bypass
vendors:
  - Wikimedia
products:
  - MediaWiki
references:
  - https://phabricator.wikimedia.org/T435026
  - https://bombobombone.github.io/posts/cve-2026-102975/
  - https://vulners.com/cve/CVE-2026-102975
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit MediaWiki roles and permissions for separation of viewsuppressed and suppressrevision rights
      owner: IT Operations
      due: 48h
      evidence: Source document describes the vulnerability as depending on specific permission separation.
  enrichment_needed:
    - item: Verify patched version for your specific MediaWiki deployment
      owner: IT Operations
      reason: Ensure the current environment is running a version that incorporates the fix for T435026.
      evidence: Phabricator ticket T435026
  mitigation_plan:
    - priority: immediate
      action: Review MediaWiki audit logs for 'action=revisiondelete' activity from unauthorized accounts
      owner: SOC
      addresses: CVE-2026-102975
      evidence: Source identifies API endpoint usage for exploitation.
---

CVE-2026-102975 identifies a security vulnerability in MediaWiki where the `action=revisiondelete` API fails to properly validate the `suppressrevision` permission. When a request includes the `suppress=no` parameter, the system erroneously allows the operation if the caller possesses `viewsuppressed` and certain revision management rights (such as `deleterevision` or `deletelogentry`), even if they lack the elevated `suppressrevision` privilege.

This flaw allows an attacker to interact with the API to unsuppress sensitive revision content that should remain restricted, effectively exposing data intended for administrative suppression only. The vulnerability was reported by Marco Paciaroni and a public proof-of-concept (PoC) exploit script written in Python is available. Defenders should review MediaWiki permission configurations and ensure that the `suppressrevision` right is correctly restricted to authorized administrative roles. The issue is tracked via Phabricator ticket T435026.

## Impact

The vulnerability results in an unauthorized exposure of suppressed or restricted wiki revision content. In production environments, this can lead to the accidental or malicious disclosure of private information, internal communications, or sensitive draft content that has been formally suppressed by administrators. The scope of impact is limited to wiki instances where granular permissions have been separated, allowing users to hold `viewsuppressed` without the corresponding `suppressrevision` authority.

## Recommendation

- Audit MediaWiki group permissions to ensure that the `suppressrevision` right is exclusively held by trusted administrative users.
- Review MediaWiki installation logs and audit trails for unauthorized or unexpected `action=revisiondelete` API calls from accounts lacking the `suppressrevision` right.
- Apply security patches or updates provided by the MediaWiki project addressing the flaw described in Phabricator ticket T435026.
- Monitor webserver access logs for anomalous traffic patterns directed at the MediaWiki API, specifically targeting the `action=revisiondelete` endpoint.
