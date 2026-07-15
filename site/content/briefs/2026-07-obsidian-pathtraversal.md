---
title: Authenticated Path Traversal in Obsidian Local REST API
slug: 2026-07-obsidian-pathtraversal
description: An authenticated path traversal vulnerability (GHSA-62gx-5q78-wrvx) in the Obsidian Local REST API's `/vault/{path}` endpoints allows an attacker to bypass path normalization checks using URL-encoded `%2F` sequences, enabling arbitrary file read, write, and delete operations outside the intended vault directory with the privileges of the Obsidian process.
date: "2026-07-15T21:58:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - vulnerability
  - obsidian
vendors:
  - Obsidian
products:
  - obsidian-local-rest-api (prior to 4.1.3)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: A literal `../` is resolved/rejected at the routing layer (→ 404), but `%2F` is not a separator there, so `..%2F..%2F` survives routing and is only turned into a real `/` by the handler's `decodeURIComponent`, reconstituting a `../` traversal that walks out of the vault.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'An authenticated client can read, write, or delete arbitrary files on the host... READ outside the vault (returns 200 + the target file''s real bytes): curl ... /etc/passwd'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Destruction
    evidence: An authenticated client can read, write, or delete arbitrary files on the host... arbitrary file read / write / delete outside the Obsidian vault
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: ""
    evidence: 'An authenticated client can read, write, or delete arbitrary files on the host... WRITE outside the vault (creates a file on disk outside the vault root): curl ... /tmp/canary.txt'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-62gx-5q78-wrvx
rules:
  - title: Detect GHSA-62gx-5q78-wrvx Path Traversal in Obsidian Local REST API
    description: Detects exploitation attempts of GHSA-62gx-5q78-wrvx, an authenticated path traversal vulnerability in the Obsidian Local REST API, by looking for URL-encoded directory traversal sequences in the URI path of requests to `/vault/` endpoints.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - webserver
rules_count: 1
---

A critical authenticated path traversal vulnerability, tracked as GHSA-62gx-5q78-wrvx, has been identified in the Obsidian Local REST API plugin (versions prior to 4.1.3). This flaw allows an authenticated client to perform arbitrary file read, write, and delete operations on the host system. The vulnerability arises because the plugin's `/vault/{path}` endpoints percent-decode request paths *after* the Express framework has already routed and normalized them. This timing issue allows URL-encoded directory traversal sequences, specifically `..%2F..%2F`, to bypass initial routing layer checks. Once decoded by the handler, these sequences are reinterpreted as real directory traversals (`../`), escaping the intended vault directory without further confinement checks. This poses a significant risk as attackers can access sensitive files (e.g., SSH keys, browser profiles), modify system configurations, or destroy critical data, especially in deployments where the API serves as a backend for agents or other automated systems.

## Attack Chain

1. An authenticated attacker, possessing a valid API key for the Obsidian Local REST API, crafts a malicious HTTP request.
2. The attacker targets one of the vulnerable `/vault/{path}` endpoints (GET, PUT, PATCH, POST, or DELETE).
3. The crafted request includes URL-encoded directory traversal sequences like `..%2F` or `%2e%2e` within the `path` component of the URL.
4. The Express framework routes the request; however, it does not normalize or reject the encoded `..%2F` sequences, allowing them to reach the API handler.
5. Inside the Obsidian Local REST API handler, the `decodeURIComponent` function is applied to the request path.
6. This decoding step converts `..%2F` into `../`, effectively reconstituting a functional directory traversal path.
7. The API handler then passes this unconfined, escaped path directly to the Obsidian vault adapter's file operations (e.g., `readBinary`, `getAbstractFileByPath`).
8. With the reconstructed path, the Obsidian process, running with its current user's privileges, performs the requested operation (read, write, or delete) on arbitrary files outside the configured vault directory.

## Impact

Successful exploitation of this vulnerability enables an authenticated attacker to read, write, or delete any file on the host system that the Obsidian process has permissions to access. This can lead to the compromise of sensitive user data, including SSH keys, browser profiles, dotfiles, and credentials stored in the user's home directory. In scenarios where the Obsidian Local REST API is used as a backend for multi-component platforms (MCPs) or LLM agents, a prompt injection or malicious client could leverage this to elevate its capabilities from confined note editing to full host filesystem manipulation, leading to widespread data destruction, system modification, or even remote code execution.

## Recommendation

* Update the `obsidian-local-rest-api` plugin to version 4.1.3 or higher immediately to apply the vendor's patch.
* Deploy the `Detect GHSA-62gx-5q78-wrvx Path Traversal in Obsidian Local REST API` Sigma rule to your SIEM to detect attempted exploitation involving URL-encoded traversal sequences in webserver logs.
* Monitor webserver access logs for the `/vault/` endpoint for unusual activity, specifically `cs-uri-stem` values containing `%2F` or `%2e%2e` that indicate path traversal attempts.
