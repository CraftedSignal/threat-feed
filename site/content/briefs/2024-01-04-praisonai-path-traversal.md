---
title: PraisonAI Recipe Registry Path Traversal Vulnerability
slug: 2024-01-04-praisonai-path-traversal
description: A path traversal vulnerability exists in PraisonAI's recipe registry publish endpoint, allowing attackers to write files outside the registry root by manipulating the manifest file in a recipe bundle, despite eventual validation failure.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-write
  - praisonai
vendors:
  - PraisonAI
products:
  - PraisonAI Recipe Registry
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-r9x3-wx45-2v7f
rules:
  - title: PraisonAI Recipe Registry Path Traversal Attempt
    description: Detects attempts to exploit the PraisonAI recipe registry path traversal vulnerability by monitoring file creation events for filenames containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - file_event
      - linux
  - title: PraisonAI Recipe Registry HTTP 400 Errors with Path Traversal
    description: Detects HTTP 400 errors in web server logs associated with recipe publish requests, indicating potential path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI's recipe registry is vulnerable to a path traversal issue (CVE-2026-39308) affecting versions up to and including 4.5.112. The vulnerability arises in the `publish` endpoint due to insufficient validation of the `name` and `version` fields within the `manifest.json` file of an uploaded recipe bundle. A malicious actor can inject `../` sequences into these fields, causing the registry server to write files to arbitrary locations outside the designated registry root. This occurs because the server creates the directory structure based on the manifest values before validating them against the URL parameters. Although the server eventually rejects the request with a HTTP 400 error if a mismatch is detected, the out-of-root artifact remains on the filesystem, posing a significant security risk. This allows for arbitrary file writes, potentially leading to integrity and availability issues.

## Attack Chain

1. An attacker crafts a malicious `.praison` recipe bundle.
2. The attacker modifies the `manifest.json` file within the bundle, injecting `../` sequences into the `name` field, for example setting `"name": "../../outside-dir"`.
3. The attacker sends a `POST` request to the `/v1/recipes/{name}/{version}` endpoint, uploading the malicious bundle, seemingly targeting a safe location such as `/v1/recipes/safe/1.0.0`.
4. The `RegistryServer._handle_publish()` function parses the request and writes the uploaded `.praison` file to a temporary path.
5. The `LocalRegistry.publish()` function opens the tarball, reads the attacker-controlled `manifest.json`, and constructs a path based on the malicious `name` and `version` fields: `self.recipes_path / name / version`.
6. The server creates directories based on the manipulated path using `recipe_dir.mkdir(parents=True, exist_ok=True)`, effectively traversing out of the intended registry root.
7. The server copies the uploaded bundle to the out-of-root destination.
8. The server then validates the manifest values against the URL parameters. Because they don't match, the server attempts to delete the file but it still persists due to the path traversal. The server returns an HTTP 400 error, but the malicious file has already been written outside the registry root.

## Impact

This vulnerability allows for arbitrary file write operations outside the intended registry root, creating a high integrity risk. Successful exploitation can lead to the creation or overwriting of critical system files, potentially leading to denial-of-service or privilege escalation. While the provided PoC demonstrates a single file write, the ability to write to arbitrary locations significantly broadens the attack surface. Impacted parties include registry operators running the PraisonAI recipe registry service and any deployment that allows remote recipe publication. If adjacent writable locations contain sensitive application data or service files, the impact can be substantial.

## Recommendation

*   Deploy the Sigma rule `PraisonAI Recipe Registry Path Traversal Attempt` to detect attempts to exploit this vulnerability based on the creation of files with path traversal sequences in their names (file_event logs).
*   Upgrade to a patched version of PraisonAI that includes validation of `manifest.json` `name` and `version` fields prior to any filesystem write.
*   Monitor web server logs for HTTP 400 errors associated with recipe publish requests and investigate the associated uploaded files for path traversal attempts (webserver logs).
*   Implement input validation for recipe names and versions on the client-side to prevent users from creating recipes with malicious names.
