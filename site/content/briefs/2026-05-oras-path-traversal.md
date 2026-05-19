---
title: ORAS Java SDK Path Traversal Vulnerability via Malicious Image Title Annotation
slug: 2026-05-oras-path-traversal
description: The `pullArtifact` methods in `Registry` and `OCILayout` use the `org.opencontainers.image.title` annotation from a pulled manifest as a filename, resolving it against the caller supplied output directory without normalization or a containment check, allowing a manifest publisher to write blobs outside of the intended target directory.
date: "2026-05-19T15:48:26Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - path-traversal
  - oras
  - java
vendors:
  - oras
products:
  - oras-java-sdk (<= 0.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xm96-gfjx-jcrc
rules:
  - title: Detect ORAS Java SDK Path Traversal Attempt via Image Title
    description: Detects a path traversal attempt in ORAS Java SDK by monitoring for abnormal file creation events originating from the oras-java-sdk where the target path contains directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
  - title: Detect ORAS Java SDK Path Traversal - Absolute Path File Creation
    description: Detects an attempt to write to an absolute path using ORAS Java SDK, which could indicate a path traversal vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The ORAS (OCI Repository As Storage) Java SDK is vulnerable to a path traversal issue in the `pullArtifact` methods of the `Registry` and `OCILayout` classes. This vulnerability arises because the SDK uses the `org.opencontainers.image.title` annotation from a pulled OCI manifest as a filename without proper sanitization. An attacker who can publish a malicious OCI manifest with a crafted `org.opencontainers.image.title` annotation can cause the SDK to write a layer's blob to an arbitrary location accessible to the JVM process. This issue affects versions 0.6.1 and earlier of the `oras-java-sdk`. Exploitation can lead to arbitrary file writes, potentially overwriting critical system files or introducing malicious code.

## Attack Chain

1. An attacker crafts a malicious OCI manifest.
2. The attacker sets the `org.opencontainers.image.title` annotation within a layer of the crafted manifest to a path that includes directory traversal sequences (e.g., `../../`) or an absolute path.
3. The attacker publishes the malicious OCI manifest to a registry.
4. A victim application uses the ORAS Java SDK to pull an artifact from the registry using `Registry.pullArtifact` or `OCILayout.pullArtifact`.
5. The `pullArtifact` method retrieves the layer's blob and its associated metadata, including the malicious `org.opencontainers.image.title` annotation.
6. The SDK uses `Path.resolve` to combine the user-supplied output directory with the malicious path from the `org.opencontainers.image.title` annotation.
7. The SDK attempts to copy the layer's blob to the resolved path using `Files.copy` with the `REPLACE_EXISTING` option.
8. Due to the path traversal or absolute path in the annotation, the blob is written to a location outside the intended output directory, potentially overwriting existing files.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to locations accessible to the JVM process running the ORAS Java SDK. This could lead to:
*   Overwriting critical system files, causing denial of service.
*   Writing malicious code (e.g., a web shell) to a location where it can be executed, leading to remote code execution.
*   Compromising the integrity of data stored by the application using the ORAS Java SDK.
The severity is high due to the potential for remote code execution and the ease of exploitation by simply publishing a malicious manifest.

## Recommendation

*   Upgrade to a patched version of the `oras-java-sdk` that addresses this vulnerability (versions later than 0.6.1).
*   As a temporary mitigation, implement input validation on the `org.opencontainers.image.title` annotation before passing it to the `pullArtifact` method.
*   Deploy the Sigma rule "Detect ORAS Java SDK Path Traversal Attempt via Image Title" to detect potential exploitation attempts.
*   Monitor network traffic for connections to known malicious container registries.
