---
title: SiYuan Publish Reader Path Traversal via removeUnusedAttributeView
slug: 2026-04-siyuan-path-traversal
description: A path traversal vulnerability exists in SiYuan's publish service via the `/api/av/removeUnusedAttributeView` endpoint, allowing a publish-service Reader to delete arbitrary `.json` files under the workspace path reachable from `data/storage/av/` using traversal payloads.
date: "2026-04-11T12:00:00Z"
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

SiYuan, a note-taking application, is vulnerable to a path traversal attack through its publish service. The vulnerability lies in the `/api/av/removeUnusedAttributeView` endpoint, which can be accessed by users with `RoleReader` permissions. Publish requests are forwarded upstream with a valid JWT, bypassing intended access controls.  The `removeUnusedAttributeView` handler accepts an attacker-controlled `id` parameter without proper validation and uses it in a file system delete operation…
