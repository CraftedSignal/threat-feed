---
title: Denial of Service via Cyclic Plugin Reparenting in django CMS
slug: 2026-08-django-cms-dos
description: An authenticated user with plugin-change permissions can exploit the move_plugin endpoint in django CMS to create cyclic tree structures, causing resource exhaustion and denial of service during recursive SQL operations.
date: "2026-08-24T21:57:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - django CMS
products:
  - django CMS (5.0.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Doing so creates a cycle in the plugin tree, after which the recursive descendant/ancestor SQL queries loop without terminating, stalling the request worker.
    confidence_band: high
cves:
  - id: CVE-2026-54623
    cvss: 7.1
    epss: 0.00345
references:
  - https://github.com/advisories/GHSA-8jj7-4v57-frf5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54623
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade django CMS to version 5.0.8
      owner: IT Operations
      due: 72h
      evidence: 'Fixed in 5.0.8: move_plugin now rejects (HTTP 400) any move that would place a plugin inside itself'
  mitigation_plan:
    - priority: immediate
      action: Review and audit administrative plugin permissions
      owner: Security Operations
      addresses: CVE-2026-54623
      evidence: Requires CMS_PERMISSION/plugin-change permission on a placeholder.
---

The django CMS application is vulnerable to a denial-of-service (DoS) condition stemming from an improper validation of the `move_plugin` administrative endpoint (CVE-2026-54623). An authenticated user with sufficient permissions to modify plugins can purposefully move a plugin to be a child of one of its own descendants. Because the underlying recursive SQL queries used to calculate ancestors and descendants lack cycle detection or recursion depth limits, this creates an infinite loop in the database worker process. This vulnerability affects django CMS versions prior to 5.0.8. When an attacker induces this state, any subsequent request attempting to render, copy, or delete the affected plugin tree will hang, leading to application worker exhaustion and potential service outage.

## Attack Chain

1. Attacker authenticates to the django CMS dashboard with staff-level permissions.
2. Attacker identifies a target plugin tree within a placeholder.
3. Attacker triggers the `move_plugin` functionality via the administrative interface.
4. Attacker sends a specially crafted POST request to `move_plugin` with the `plugin_parent` parameter targeting a child or descendant of the currently moved plugin.
5. The application backend accepts the request without validating the cyclic dependency.
6. The backend updates the database, setting the `parent_id` and creating a closed-loop structure in the plugin tree.
7. Attacker triggers a legitimate action (e.g., viewing the page, editing the tree) that calls `get_descendants()` or `get_ancestors()`.
8. The database engine executes an unconstrained `WITH RECURSIVE` CTE, causing the application thread to hang and eventually exhausting worker capacity (DoS).

## Impact

Successful exploitation results in a persistent denial-of-service condition for the affected placeholder. The application becomes unresponsive for any administrative or front-end operation involving the corrupted plugin tree. The vulnerability requires authenticated access, limiting the scope to internal users or accounts with plugin-change permissions; however, it allows for targeted service disruption within the CMS environment.

## Recommendation

Prioritized actions for detection and mitigation:
* Patch the django CMS installation to version 5.0.8 or later to incorporate the required cycle validation logic in the `move_plugin` endpoint.
* Audit logs for administrative users performing high-frequency or anomalous `move_plugin` POST requests that might indicate attempts to manipulate the plugin tree structure.
* Monitor application web server logs for HTTP 500 or timeout errors occurring specifically during administrative plugin operations, which may indicate the presence of cyclic tree corruption.
* Restrict `CMS_PERMISSION` and plugin-change permissions to a minimal set of trusted administrative accounts to reduce the threat surface.
