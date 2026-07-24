---
title: electron-updater Vulnerability Leaks Credentials on Cross-Origin Redirects
slug: 2026-07-electron-updater-credential-leak
description: A vulnerability, CVE-2026-54673, in `electron-builder`'s `builder-util-runtime` package, specifically in its HTTP redirect handler, allows credential headers like `PRIVATE-TOKEN` (GitLab personal access tokens) and mixed-case `Authorization` tokens to be improperly forwarded to attacker-controlled cross-origin redirect destinations, resulting in credential disclosure and enabling unauthorized access to private GitLab resources.
date: "2026-07-24T14:06:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - exfiltration
  - vulnerability
  - electron
  - software-supply-chain
  - gitlab
vendors:
  - electron-builder
  - GitLab
products:
  - builder-util-runtime < 9.7.0
  - electron-builder < 26.15.0
  - electron-updater
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The HTTP redirect handler ... allowed credential headers ... to be improperly forwarded to attacker-controlled cross-origin redirect destinations.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: 'The request to the redirect destination is issued with PRIVATE-TOKEN: <token> present in the headers. ... An attacker who controls or can observe the redirect destination receives the token.'
    confidence_band: high
cves:
  - id: CVE-2026-54673
    epss: 0.00235
references:
  - https://github.com/advisories/GHSA-p2f4-r6v6-j797
---

A significant vulnerability, tracked as CVE-2026-54673, has been identified in the `builder-util-runtime` package, a core component of `electron-builder`. This flaw impacts versions of `builder-util-runtime` prior to 9.7.0 (and `electron-builder` prior to v26.15.0). The vulnerability stems from an insufficient credential stripping mechanism within the HTTP redirect handler (`HttpExecutor.prepareRedirectUrlOptions`). Specifically, headers such as `PRIVATE-TOKEN` (used for GitLab personal access tokens) and `Authorization` when using mixed-case keys were not correctly stripped during cross-origin redirects. This allows sensitive credentials to be inadvertently forwarded to third-party, potentially malicious, redirect destinations. The issue primarily affects updater flows, particularly those interacting with private GitLab instances that commonly redirect asset downloads to external object storage. The vulnerability can lead to unauthorized access to private source code, packages, or release artifacts.

## Attack Chain

1. The `electron-updater` component initiates an update check, requesting a release asset from a trusted source, such as a private GitLab instance, while supplying authentication credentials (e.g., `PRIVATE-TOKEN` or `Authorization` header).
2. The trusted GitLab origin returns an HTTP 3xx redirect response, directing the client to an external object-storage origin (e.g., S3, GCS) for the asset download.
3. The `HttpExecutor.prepareRedirectUrlOptions` function within `builder-util-runtime` is invoked to handle the redirect and conditionally strip sensitive headers.
4. Due to a case-sensitive check, `headers?.authorization` evaluates to `undefined` for `PRIVATE-TOKEN` or mixed-case `Authorization` headers.
5. The sensitive header (e.g., `PRIVATE-TOKEN` or `Authorization` with mixed casing) is not removed by the vulnerable code path.
6. The `electron-updater` client then issues a request to the cross-origin redirect destination, including the sensitive, unstripped credential header.
7. An attacker controlling or observing the redirect destination receives the sensitive credential token.

## Impact

This is a critical credential disclosure vulnerability, CVE-2026-54673, that can inadvertently expose sensitive authentication tokens. Specifically, it can leak GitLab personal access tokens (`PRIVATE-TOKEN`) and Bearer/OAuth tokens when they are sent under a mixed-case `Authorization` key. Any other custom credential header not exactly named "authorization" in lowercase would also be exposed. The disclosure of a GitLab personal access token grants an attacker the same repository and API permissions as the token itself, leading to unauthorized access to private source code repositories, software packages, and release artifacts. Such access can enable intellectual property theft, code manipulation, or further supply chain attacks.

## Recommendation

* Update `builder-util-runtime` to version `9.7.0` or higher immediately, or `electron-builder` to `v26.15.0` or higher to patch CVE-2026-54673.
* Review all instances of `electron-updater` in your environment to ensure they are running patched versions.
* Avoid using authenticated GitLab updater flows on vulnerable versions (e.g., `builder-util-runtime` < 9.7.0).
