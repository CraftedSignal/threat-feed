---
title: Open WebUI Broken Authorization Allows Task Cancellation
slug: 2026-05-open-webui-task-kill
description: Open WebUI is vulnerable to broken object-level authorization, allowing low-privilege authenticated users to enumerate and stop global background tasks across the system, leading to a denial-of-service condition and is tracked as CVE-2026-45399 and CVE-2025-63681.
date: "2026-05-14T20:32:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:openwebui:open_webui:0.6.41:*:*:*:*:*:*:*
tags:
  - authorization
  - denial-of-service
  - cve-2026-45399
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2025-63681
    cvss: 4.3
    epss: 0.00013
references:
  - https://github.com/advisories/GHSA-8jjp-r2w2-4v22
  - https://github.com/open-webui/open-webui/commit/e7ff4768f8ffe1924b4576381c9e45e8a64350e4
rules:
  - title: Detect Open WebUI Task Enumeration
    description: Detects attempts to enumerate all active tasks via the /api/tasks endpoint, potentially indicating unauthorized access to task information (CVE-2026-45399, CVE-2025-63681).
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Open WebUI Task Cancellation
    description: Detects attempts to stop tasks via the /api/tasks/stop/{task_id} endpoint, which could indicate unauthorized task cancellation (CVE-2026-45399, CVE-2025-63681).
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.8.12 and earlier suffer from a broken object-level authorization vulnerability that allows authenticated, low-privilege users to enumerate and stop tasks belonging to other users. This vulnerability, identified as CVE-2026-45399 and a prior disclosure as CVE-2025-63681, enables an attacker to disrupt system-wide chat usage by repeatedly canceling active tasks. The vulnerability stems from insufficient authorization checks on the `/api/tasks` and `/api/tasks/stop/{task_id}` endpoints, which operate on a global task namespace. A fix was implemented in version 0.9.0 of Open WebUI. This issue highlights the risk of relying on weak authorization schemes, where simply being an authenticated user grants access to sensitive system functions.

## Attack Chain

1. An attacker obtains a valid user account on the Open WebUI instance.
2. The attacker authenticates to the Open WebUI instance using their credentials.
3. The attacker sends a GET request to `/api/tasks` to enumerate all active task IDs on the system.
4. The server returns a list of task IDs, including those belonging to other users.
5. The attacker selects a task ID belonging to another user.
6. The attacker sends a POST request to `/api/tasks/stop/{task_id}`, replacing `{task_id}` with the target task ID.
7. The server, lacking proper authorization checks, attempts to stop the specified task.
8. The targeted user's task is interrupted, causing disruption to their ongoing activity.

## Impact

This vulnerability impacts all users in a multi-user Open WebUI deployment, particularly those running background tasks such as chat generation. A single low-privilege user can effectively cause a denial-of-service by continuously canceling tasks, making the chat functionality unusable for other users. This affects integrity and availability, allowing unauthorized interruption of legitimate operations.

## Recommendation

*   Upgrade to Open WebUI version 0.9.0 or later to remediate CVE-2026-45399 and CVE-2025-63681, which addresses the broken object-level authorization.
*   Deploy the Sigma rule "Detect Open WebUI Task Enumeration" to identify potential exploitation attempts using the `/api/tasks` endpoint.
*   Deploy the Sigma rule "Detect Open WebUI Task Cancellation" to detect unauthorized task cancellation attempts via the `/api/tasks/stop/{task_id}` endpoint.
