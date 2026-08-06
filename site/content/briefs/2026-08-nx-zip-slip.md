---
title: Zip-Slip Vulnerability in Nx Self-Hosted Remote Cache
slug: 2026-08-nx-zip-slip
description: A Zip-Slip vulnerability in the Nx self-hosted HTTP remote cache allows a malicious cache server to write files to arbitrary locations on a client machine, leading to potential remote code execution.
date: "2026-08-06T21:29:52Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Nx
products:
  - nx
  - '@nx/s3-cache'
  - '@nx/gcs-cache'
  - '@nx/azure-cache'
  - '@nx/shared-fs-cache'
  - '@nx/powerpack-s3-cache'
  - '@nx/powerpack-gcs-cache'
  - '@nx/powerpack-azure-cache'
  - '@nx/powerpack-shared-fs-cache'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The insecure extraction logic allows for arbitrary file writes which can be escalated to remote code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vp3h-ghgh-jr7g
  - https://github.com/nrwl/nx/pull/36116
  - https://nx.dev/docs/reference/deprecated/self-hosted-cache-packages
---

Nx versions 20.8.0 through 22.7.6 and 23.0.0 through 23.0.1 contain a critical Zip-Slip vulnerability in their self-hosted HTTP remote cache implementation. The vulnerability stems from an insecure extraction routine that fails to validate file paths within downloaded tar archives. By leveraging a compromised or malicious self-hosted remote cache server, an attacker can provide a crafted tar archive containing directory traversal sequences. These sequences cause the client-side Nx extraction logic to write files outside of the intended directory, potentially overwriting critical system files or placing malicious binaries in executable paths. This flaw is specific to self-hosted cache configurations (`NX_SELF_HOSTED_REMOTE_CACHE_SERVER` and related packages); default local caching and Nx Cloud remain unaffected.

## Attack Chain

1. The attacker gains control of the infrastructure hosting the Nx remote cache server or performs a Man-in-the-Middle (MITM) attack to intercept HTTP traffic.
2. The Nx client requests a cached task output artifact from the remote cache server.
3. The malicious server responds with a crafted gzipped tar archive containing entries with directory traversal characters (e.g., ../../).
4. The Nx client receives the payload and passes it to the vulnerable extraction routine.
5. The routine joins the untrusted archive entry path to the base output directory without validation.
6. The `tar` extraction process writes the file to an arbitrary location on the client filesystem based on the traversal path.
7. The attacker targets sensitive locations, such as startup folders or configuration files, to achieve remote code execution upon the next system or application restart.

## Impact

The vulnerability poses a high risk to organizations using self-hosted Nx remote caches. Successful exploitation allows for arbitrary file writes with the privileges of the user running the Nx workspace commands. This can lead to full system compromise, exfiltration of sensitive source code or credentials, and persistent remote code execution within the CI/CD pipeline or developer environments.

## Recommendation

- Upgrade the `nx` core package to versions `22.7.7` or `23.0.2` immediately to patch the insecure extractor.
- Migrate away from deprecated self-hosted cache packages (`@nx/s3-cache`, `@nx/gcs-cache`, `@nx/azure-cache`, `@nx/shared-fs-cache`, and their Powerpack counterparts) as these remain vulnerable and lack patches.
- Audit infrastructure hosting remote caches to ensure secure access controls and prevent unauthorized server-side modifications.
- Use network-level security, such as TLS and mutual authentication, to prevent MITM attacks on the remote cache traffic.
