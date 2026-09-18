---
title: Unauthenticated Administrative Access in Semantic MediaWiki smwtask API
slug: 2026-09-smwtask-auth-bypass
description: The Semantic MediaWiki smwtask API module fails to enforce authorization, enabling unauthenticated remote attackers to perform sensitive information disclosure, queue administrative maintenance jobs, and manipulate stored semantic data.
date: "2026-09-18T19:52:03Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - api-security
  - broken-access-control
  - webserver
vendors:
  - Semantic MediaWiki
products:
  - Semantic MediaWiki (3.0.0-7.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The smwtask API module in Semantic MediaWiki lacks authorization checks, allowing unauthenticated users to access administrative maintenance tasks.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jr78-w6w5-m8f8
rules:
  - title: Detect Unauthenticated Access to Semantic MediaWiki smwtask
    description: Detects HTTP POST requests to the smwtask API module, which lacks proper authorization checks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Semantic MediaWiki to 7.3.0 or higher.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly states upgrading to 7.3.0+ resolves the issue.
    - action: Apply the LocalSettings.php patch to unset the smwtask API module if immediate upgrade is not possible.
      owner: IT Operations
      due: 4h
      evidence: Source provides a local mitigation via LocalSettings.php.
  hunt_leads:
    - lead: Search web logs for POST requests to /api.php with action=smwtask.
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Proof of concept demonstrates this URL/action string.
  mitigation_plan:
    - priority: immediate
      action: Disable smwtask module via PHP snippet in LocalSettings.php
      owner: IT Operations
      addresses: API authorization bypass
      evidence: Source recommended mitigation snippet.
---

Semantic MediaWiki versions 3.0.0 through 7.2.1 contain a critical authorization vulnerability in the `smwtask` API module. The module implements a `needsToken('csrf')` check, but because MediaWiki provides a fixed, public CSRF token (`+\`) to anonymous users, this check fails to prevent unauthenticated access. Consequently, an attacker can invoke administrative tasks that are otherwise restricted to users with the `smw-admin` right via the `Special:SMWAdmin` web interface. The vulnerability allows attackers to query internal database statistics, enumerate object IDs, inject arbitrary maintenance jobs (such as fulltext search rebuilds or entity disposal), and force synchronous job execution, leading to both information disclosure and potential data integrity loss.

## Attack Chain

1. Attacker sends a request to `api.php?action=query&meta=tokens&type=csrf` to retrieve the anonymous session CSRF token.
2. The server responds with the default public token value `+\`.
3. Attacker constructs an HTTP POST request to `api.php?action=smwtask` using the `+\` token to satisfy the CSRF check.
4. Attacker calls `table-statistics` via the `task` parameter to enumerate internal object-ID spaces and database metrics.
5. Attacker calls `insert-job` to enqueue administrative tasks, such as `smw.entityIdDisposer` or `smw.fulltextSearchTableRebuild`, targeting specific wiki identifiers.
6. Attacker calls `run-joblist` with a serialized parameters object to force synchronous execution of the injected maintenance jobs.
7. The application executes the requested administrative jobs with the privileges of the system backend, resulting in unauthorized data modification or performance degradation.

## Impact

Successful exploitation allows unauthenticated actors to bypass access controls intended for administrators. Observed consequences include unauthorized disclosure of database internal structures and statistics, resource exhaustion via forced synchronous job execution, and the modification or deletion of semantic data entities. The severity of the impact scales with the size of the wiki's semantic store and the criticality of the targeted maintenance operations.

## Recommendation

Prioritize the immediate remediation of affected Semantic MediaWiki instances by upgrading to version 7.3.0 or later. If an immediate upgrade is not feasible, implement a hotfix in the site's `LocalSettings.php` to unregister the vulnerable API module: 

```php
$wgExtensionFunctions[] = static function () {
 unset( $GLOBALS['wgAPIModules']['smwtask'] );
};
```

Deploy detection rules to monitor for anomalous POST requests to the `api.php` endpoint containing `action=smwtask` and verify the identity of the requesting user.
