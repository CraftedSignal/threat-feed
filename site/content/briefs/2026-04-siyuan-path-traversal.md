---
title: SiYuan Publish Reader Path Traversal via removeUnusedAttributeView
slug: 2026-04-siyuan-path-traversal
description: A path traversal vulnerability exists in SiYuan's publish service via the `/api/av/removeUnusedAttributeView` endpoint, allowing a publish-service Reader to delete arbitrary `.json` files under the workspace path reachable from `data/storage/av/` using traversal payloads.
date: "2026-04-11T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - siyuan
  - file-deletion
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-vw86-c94w-v3x4
rules:
  - title: SiYuan Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in SiYuan's removeUnusedAttributeView endpoint by identifying requests with path traversal sequences in the 'id' parameter.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: SiYuan Config File Deletion Attempt
    description: Detects attempts to delete the SiYuan configuration file (conf/conf.json) via the removeUnusedAttributeView endpoint path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan, a note-taking application, is vulnerable to a path traversal attack through its publish service. The vulnerability lies in the `/api/av/removeUnusedAttributeView` endpoint, which can be accessed by users with `RoleReader` permissions. Publish requests are forwarded upstream with a valid JWT, bypassing intended access controls.  The `removeUnusedAttributeView` handler accepts an attacker-controlled `id` parameter without proper validation and uses it in a file system delete operation. This allows attackers to use "../" sequences to traverse directories and delete arbitrary `.json` files within the SiYuan workspace. This vulnerability was disclosed on 2026-04-10 and impacts versions prior to the fix. Successful exploitation can lead to persistent destruction of Attribute View definitions, deletion of global workspace configuration, corruption of user state, and broken UI behavior.

## Attack Chain

1.  Attacker gains publish-reader access, or anonymous publish access if publish auth is disabled.
2.  Attacker crafts a malicious POST request to `/api/av/removeUnusedAttributeView` with a path traversal payload in the `id` parameter, such as `../../../conf/conf`.
3.  The publish reverse proxy forwards the request to the kernel, injecting an `X-Auth-Token` with `RoleReader`.
4.  The `CheckAuth` middleware allows the request because `RoleReader` is permitted.
5.  The `removeUnusedAttributeView` handler extracts the attacker-controlled `id` value without validation.
6.  The application constructs a file path using `filepath.Join(util.DataDir, "storage", "av", id+".json")`, resulting in a path outside the intended `data/storage/av/` directory (e.g., `<workspace>/conf/conf.json`).
7.  The application attempts to delete the file at the constructed path using `filelock.RemoveWithoutFatal(absPath)`.
8.  The targeted `.json` file is deleted, leading to persistent destruction of Attribute View definitions, deletion of global workspace configuration, or corruption of user state.

## Impact

Successful exploitation of this vulnerability allows an attacker with publish-reader access to delete arbitrary `.json` files under the workspace path reachable from `data/storage/av/`. This can lead to persistent destruction of Attribute View definitions, deletion of global workspace configuration, deletion of local storage and outline state, corruption of user state that survives reload, and forced reset/recovery flows or broken UI behavior. The impact ranges from broken UI functionality to complete data loss and application instability.

## Recommendation

*   Deploy the "SiYuan Path Traversal Attempt" Sigma rule to detect attempts to exploit the vulnerability via the `removeUnusedAttributeView` endpoint.
*   Block requests to `/api/av/removeUnusedAttributeView` containing path traversal sequences (e.g., `../`) in the `id` parameter at the WAF or reverse proxy.
*   Apply the remediation steps outlined in the advisory, specifically implementing input validation and subpath enforcement to prevent path traversal, as referenced in the Overview.
