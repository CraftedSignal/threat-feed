---
title: esm.sh Path Traversal Vulnerability via package.json Browser Field
slug: 2026-05-esmsh-path-traversal
description: A local file inclusion (LFI) vulnerability exists in the esbuild plugin's handling of the `browser` field in `package.json` within esm.sh, allowing an attacker to publish a malicious npm package that causes the server to read arbitrary files from the host filesystem.
date: "2026-05-12T22:25:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path traversal
  - local file inclusion
  - npm
  - esbuild
vendors:
  - esm-dev
products:
  - esm.sh
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rg65-45m7-hq57
  - https://www.npmjs.com/package/chess-sec-utils1
rules:
  - title: Detect esm.sh Path Traversal Attempt via Package Request
    description: Detects attempts to exploit CVE-2026-44594 by identifying requests to esm.sh for packages with suspicious path traversal sequences in the package name or version.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect esm.sh Path Traversal via Browser Field Remapping
    description: Detects CVE-2026-44594 exploitation — Monitors process creation for esbuild invoking commands with package.json files that contain browser field remappings to suspicious file paths.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A local file inclusion (LFI) vulnerability, tracked as CVE-2026-44594, has been identified in esm.sh, specifically in the esbuild plugin's handling of the `browser` field within `package.json` files. An attacker can exploit this flaw by publishing a malicious npm package. This package, when processed by the esm.sh server during a build, allows the attacker to read arbitrary files from the server's filesystem. The vulnerability arises because the `browser` field remaps module paths to attacker-controlled values with `../` sequences, bypassing validation checks. The issue affects versions prior to commit 0593516c4cfa. Successful exploitation can lead to the exposure of sensitive information such as npm registry authentication tokens and S3 storage credentials stored in the esm.sh `config.json` file.

## Attack Chain

1. An attacker crafts a malicious npm package containing a `package.json` file.
2. The `package.json` includes a `browser` field that remaps local module paths to paths outside the intended package directory using `../` sequences.
3. The attacker publishes the malicious package to the npm registry. The package name is chess-sec-utils1, version 1.0.6.
4. A user (or automated system) requests the malicious package (e.g., `chess-sec-utils1@1.0.6`) from an esm.sh instance.
5. The esm.sh server's esbuild plugin resolves module paths during the build process.
6. The plugin uses the `browser` field remapping, which replaces the validated module path with the attacker-controlled path.
7. The server reads the file specified in the remapped path from its filesystem, subject to esbuild's loader selection (e.g., `.json`, `.txt`, `.js`).
8. The contents of the file are included in the generated JavaScript bundle and/or the source map (`sourcesContent` array), which is then served to the user.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files from the esm.sh server. This includes the `config.json` file, which may contain sensitive data such as npm registry authentication tokens and S3 storage credentials. The exposure of these credentials could allow the attacker to compromise the esm.sh infrastructure or gain unauthorized access to other resources. The proof of concept shows reading /etc/hostname, /etc/os-release and /etc/environment.

## Recommendation

*   Apply the patch suggested by the advisory to add a path validation check after the `browser` field remapping to prevent path traversal (reference: advisory content).
*   Monitor npm package installations for packages with suspicious `browser` field entries containing `../` sequences (reference: advisory content).
*   Deploy the Sigma rule to detect requests to esm.sh for packages that attempt path traversal (reference: the Sigma rule).
*   Update `go/github.com/esm-dev/esm.sh` to a version >= 0.0.0-20250616164159-0593516c4cfa.
