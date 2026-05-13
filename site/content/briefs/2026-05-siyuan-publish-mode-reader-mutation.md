---
title: SiYuan Publish-Mode Reader Configuration and Index Mutation Vulnerability
slug: 2026-05-siyuan-publish-mode-reader-mutation
description: SiYuan publish-mode Reader can mutate Conf and SQL index via 8 ungated APIs, leading to configuration changes, denial of service, data corruption, and information disclosure by manipulating cloud sync intervals, graph configurations, SQL block content, and recent-documents lists.
date: "2026-05-13T15:36:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - siyuan
  - misconfiguration
  - unauthorized_access
  - data_manipulation
vendors:
  - siyuan-note
products:
  - siyuan
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gmmv-4cc5-wr9r
  - CVE-2026-45371
rules:
  - title: Detect SiYuan Unauthorized Sync Interval Modification
    description: Detects unauthorized modification of the SiYuan sync interval via the /api/sync/setSyncInterval endpoint, potentially leading to denial of service or data divergence.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
  - title: Detect SiYuan Unauthorized Graph Configuration Modification
    description: Detects unauthorized modification of the SiYuan graph configuration via the /api/graph/getGraph endpoint, potentially disrupting graph rendering.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

SiYuan is vulnerable to unauthorized modification of server-side state due to missing authorization checks on eight API endpoints: `/api/graph/getGraph`, `/api/graph/getLocalGraph`, `/api/sync/setSyncInterval`, `/api/storage/updateRecentDocViewTime`, `/api/storage/updateRecentDocCloseTime`, `/api/storage/updateRecentDocOpenTime`, `/api/storage/batchUpdateRecentDocCloseTime`, and `/api/search/updateEmbedBlock`. These endpoints lack `model.CheckAdminRole` and `model.CheckReadonly` checks, allowing any authenticated user, including publish-service `RoleReader` and `RoleEditor` with `Editor.ReadOnly = true`, to write to the server. This can lead to atomic rewrites of the `<workspace>/conf/conf.json` file and modifications to the SQL index. This vulnerability affects all SiYuan versions up to and including v3.6.5. This is similar to previously patched vulnerabilities GHSA-6r88-8v7q-q4p2 and GHSA-4j3x-hhg2-fm2x, indicating a recurring pattern of missing authorization checks.

## Attack Chain

1.  Attacker authenticates to the SiYuan application, obtaining a JWT that passes `CheckAuth`. This can be as a publish-service `RoleReader` (anonymous publish visitor) or a `RoleEditor` against a workspace where `Editor.ReadOnly = true`.
2.  Attacker sends a POST request to `/api/sync/setSyncInterval` with a crafted JSON payload containing a malicious interval value (e.g., 30 or 43200).
3.  The server receives the request and updates the `Conf.Sync.Interval` value based on the attacker-provided interval, persisting the change to `conf.json` via `Conf.Save()`.
4.  Attacker sends a POST request to `/api/graph/getGraph` with a crafted JSON payload containing a malicious graph configuration.
5.  The server receives the request and overwrites `model.Conf.Graph.Global` from the attacker-supplied JSON and persists the entire workspace `conf.json`.
6.  Attacker sends a POST request to `/api/search/updateEmbedBlock` with a crafted JSON payload, specifying an embed-block ID and malicious content.
7.  The server receives the request and updates the `blocks` table in the SQL database, rewriting the `content` column for the specified embed-block ID.
8.  Other users accessing the SiYuan application will now see the poisoned content when the embedded block is displayed or searched.

## Impact

Successful exploitation allows unauthorized users to modify the SiYuan configuration and data, potentially leading to denial-of-service, data corruption, and information disclosure. Specifically, attackers can:

1.  Cause a denial-of-service by setting a minimal cloud sync interval (30 seconds), causing excessive battery drain and bandwidth consumption on connected clients.
2.  Effectively pause cloud sync by setting a maximal sync interval (43200 seconds), increasing the risk of data divergence.
3.  Corrupt graph rendering by providing extreme values for `maxBlocks`, `minRefs`, or `nodeSize` in the `/api/graph/getGraph` or `/api/graph/getLocalGraph` endpoints.
4.  Poison search results by injecting malicious content into embed blocks via the `/api/search/updateEmbedBlock` endpoint.
5.  Manipulate the admin's recently-opened-documents list, potentially disclosing information about publish-private notebooks via the `updateRecentDoc*` endpoints.

## Recommendation

*   Deploy the Sigma rule "Detect SiYuan Unauthorized Sync Interval Modification" to monitor for unauthorized modifications to the sync interval using the `/api/sync/setSyncInterval` endpoint.
*   Deploy the Sigma rule "Detect SiYuan Unauthorized Graph Configuration Modification" to monitor for unauthorized modifications to the graph configuration using the `/api/graph/getGraph` endpoint.
*   Apply the patch described in the advisory by adding `model.CheckAdminRole` and `model.CheckReadonly` to the affected `ginServer.Handle` calls in `kernel/api/router.go` to restrict access to these API endpoints to authorized users.
*   Monitor web server logs for POST requests to the listed API endpoints (`/api/graph/getGraph`, `/api/graph/getLocalGraph`, `/api/sync/setSyncInterval`, `/api/storage/updateRecentDocViewTime`, `/api/storage/updateRecentDocCloseTime`, `/api/storage/updateRecentDocOpenTime`, `/api/storage/batchUpdateRecentDocCloseTime`, `/api/search/updateEmbedBlock`) without corresponding administrative actions.
