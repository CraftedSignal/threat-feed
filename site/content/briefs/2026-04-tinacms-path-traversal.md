---
title: TinaCMS GraphQL Path Traversal Vulnerability
slug: 2026-04-tinacms-path-traversal
description: A path traversal vulnerability in @tinacms/graphql allows unauthenticated users to write and overwrite arbitrary files within the project root by manipulating the relativePath parameter in GraphQL mutations, leading to potential arbitrary code execution.
date: "2026-03-30T17:11:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - graphql
  - tinacms
  - arbitrary-file-write
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-v9p7-gf3q-h779
rules:
  - title: Detect TinaCMS GraphQL Path Traversal Attempt
    description: Detects attempts to exploit the TinaCMS GraphQL path traversal vulnerability by identifying suspicious `relativePath` parameters in POST requests to the `/graphql` endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect TinaCMS GraphQL Arbitrary File Write - Package.json
    description: Detects attempts to overwrite package.json file by exploiting TinaCMS GraphQL path traversal vulnerability by identifying mutations with package.json in relativePath parameter
    platform: sigma
    severity: critical
    tactics:
      - impact
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in versions 2.2.1 and earlier of `@tinacms/graphql`, a GraphQL API for TinaCMS. This flaw enables unauthenticated attackers to write and overwrite arbitrary files within the project root directory. The vulnerability stems from insufficient validation of the `relativePath` parameter within GraphQL mutations. By exploiting this weakness, attackers can overwrite critical server configuration files like `package.json` and `tsconfig.json`, inject malicious scripts into the `public/` directory, and even achieve arbitrary code execution by modifying build scripts or server-side logic files. This vulnerability poses a significant risk to systems utilizing vulnerable versions of `@tinacms/graphql`.

## Attack Chain

1. An attacker identifies a TinaCMS instance running a vulnerable version of `@tinacms/graphql` (<= 2.2.1).
2. The attacker crafts a malicious GraphQL mutation request targeting the `updateDocument` mutation.
3. Within the mutation, the attacker manipulates the `relativePath` parameter to include a path traversal sequence, such as `x\\\\..\\\\..\\\\..\\\\package.json`. The backslashes are misinterpreted on non-Windows systems.
4. The vulnerable `getValidatedPath` function fails to properly sanitize the malicious path due to the backslash bypass on non-Windows platforms.
5. The request is processed, and the server attempts to write to the attacker-specified file path.
6. The file system API resolves the path traversal sequence, leading to a write operation outside the intended directory.
7. The attacker overwrites a critical file, such as `package.json`, with malicious content.
8. The server or build process executes the modified file, resulting in arbitrary code execution or other malicious behavior.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform arbitrary file writes, leading to several critical consequences. Attackers can overwrite server configuration files, inject malicious scripts for client-side attacks, and achieve arbitrary code execution by modifying build scripts or server-side logic. The impact ranges from denial of service to complete system compromise. While the exact number of affected systems is unknown, all TinaCMS instances running `@tinacms/graphql` version 2.2.1 or earlier are susceptible.

## Recommendation

*   Upgrade `@tinacms/graphql` to a patched version (later than 2.2.1) to remediate CVE-2026-33949.
*   Deploy the Sigma rule `Detect TinaCMS GraphQL Path Traversal Attempt` to identify attempted exploitation of the vulnerability.
*   Monitor web server logs for POST requests to the `/graphql` endpoint containing suspicious `relativePath` parameters.
*   Implement strict input validation and sanitization for file paths within GraphQL mutations, regardless of the underlying operating system.
