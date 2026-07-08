---
title: 'CVE-2026-59703: repomix Local File Inclusion Vulnerability'
slug: 2026-07-repomix-lfi
description: repomix contains a local file inclusion vulnerability (CVE-2026-59703) in its git clone endpoint, allowing unauthenticated attackers to read arbitrary local git repositories and server filesystem contents by bypassing validation with crafted file:// URLs.
date: "2026-07-08T15:21:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - local-file-inclusion
  - web-vulnerability
  - cve
  - repomix
vendors:
  - repomix
products:
  - repomix < 1.14.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: repomix contains a local file inclusion vulnerability in the git clone endpoint that allows unauthenticated attackers to read arbitrary local git repositories.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: enabling unauthorized access to all tracked file contents on the server filesystem.
    confidence_band: high
cves:
  - id: CVE-2026-59703
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59703
  - https://github.com/CrazyForks/repomix/commit/c748b524f41225e7fc6f89ad0084520901a453cf
  - https://github.com/yamadashy/repomix
  - https://github.com/yamadashy/repomix/issues/1704
  - https://www.vulncheck.com/advisories/repomix-local-file-inclusion-via-file-url-scheme-in-git-clone-endpoint
rules:
  - title: Detects CVE-2026-59703 Exploitation - repomix LFI via file:// URL in git clone
    description: Detects CVE-2026-59703 exploitation - HTTP requests to the repomix git clone endpoint containing file:// URLs in parameters, indicating a local file inclusion attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical local file inclusion vulnerability, identified as CVE-2026-59703, has been discovered in `repomix`, a tool for managing git repositories. This flaw allows unauthenticated attackers to read arbitrary local git repositories and sensitive server filesystem contents. The vulnerability stems from the `isValidRemoteValue` function in `src/core/git/gitRemoteParse.ts`, which fails to block `file://` URLs. Attackers can supply these specially crafted `file://` scheme URLs via the `git clone` endpoint, bypassing validation and causing the application to pass them directly to the underlying `git clone` command. This enables unauthorized access to tracked files on the server. The vulnerability impacts `repomix` versions prior to 1.14.1. The advisory was published on July 8, 2026, highlighting the immediate need for organizations using vulnerable `repomix` instances to upgrade or implement protective measures to prevent data exfiltration.

## Attack Chain

1. Unauthenticated attacker identifies a public-facing `repomix` instance vulnerable to CVE-2026-59703 (versions < 1.14.1).
2. The attacker crafts an HTTP POST or GET request targeting the `repomix` `git clone` endpoint, embedding a `file://` URI in the `remote` parameter, e.g., `/git/clone?remote=file:///etc/passwd`.
3. The `isValidRemoteValue` function in `src/core/git/gitRemoteParse.ts` fails to properly validate and block the `file://` scheme URL.
4. `repomix` passes the attacker-supplied `file://` URI directly to the underlying `git clone` command.
5. The `git clone` command attempts to access and clone the local file path specified by the `file://` URI (e.g., `/etc/passwd`).
6. The `repomix` application returns the content of the targeted local file or directory within the HTTP response to the attacker.
7. This allows the unauthenticated attacker to read arbitrary local git repositories and other sensitive server filesystem contents, leading to data exfiltration.

## Impact

Successful exploitation of CVE-2026-59703 allows unauthenticated attackers to achieve local file inclusion, leading to the unauthorized disclosure of sensitive information. This includes access to arbitrary local git repositories, configuration files (e.g., `/etc/passwd`, database credentials), source code, and other proprietary data stored on the server's filesystem. While no specific victim count or targeted sectors have been disclosed, any organization using vulnerable `repomix` instances is at risk of significant data exfiltration and potential further compromise if credentials or other sensitive information are discovered through this vulnerability.

## Recommendation

* Patch CVE-2026-59703 by upgrading `repomix` to version 1.14.1 or higher immediately.
* Deploy the provided Sigma rule to your SIEM to detect attempts to exploit CVE-2026-59703 by monitoring webserver logs for `file://` URLs in `git clone` requests.
* Implement a Web Application Firewall (WAF) rule to block HTTP requests to the `git clone` endpoint containing `file://` URI schemes in request parameters, as described in the attack chain.
