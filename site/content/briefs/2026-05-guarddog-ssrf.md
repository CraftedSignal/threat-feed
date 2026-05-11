---
title: GuardDog SSRF and GH_TOKEN Exfiltration via Blind URL Rewrite (CVE-2026-44971)
slug: 2026-05-guarddog-ssrf
description: GuardDog versions 1.0.0 through 2.9.0 are vulnerable to Server-Side Request Forgery (SSRF) and potential `GH_TOKEN` exfiltration due to a blind URL rewrite in remote project scanning; an attacker can influence the scanned repository URL to trigger SSRF and capture the `GH_TOKEN` used by GuardDog.
date: "2026-05-11T14:46:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - credential-access
  - github
vendors:
  - GitHub
  - pip
products:
  - guarddog (>= 1.0.0, <= 2.9.0)
  - github.com
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-587r-mc96-6f2p
  - CVE-2026-44971
rules:
  - title: Detect GuardDog GH_TOKEN Exfiltration Attempt
    description: Detects CVE-2026-44971 exploitation — attempts to exfiltrate the GH_TOKEN by monitoring network connections initiated by GuardDog to non-GitHub hosts.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious URL in GuardDog Process
    description: Detects CVE-2026-44971 exploitation — detects suspicious URLs with embedded credentials in the GuardDog process command line.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

GuardDog, a dependency analysis tool, is vulnerable to Server-Side Request Forgery (SSRF) due to a flaw in its remote project scanning functionality. Specifically, versions 1.0.0 through 2.9.0 are affected. The vulnerability arises from the `ProjectScanner.scan_remote()` function, which blindly rewrites URLs without proper validation. By crafting a malicious URL that includes an attacker-controlled hostname, an attacker can redirect requests to an arbitrary server. This includes the potential for the GuardDog instance to send its configured GitHub credentials (`GH_TOKEN`) via HTTP Basic Authentication to the attacker's server. This vulnerability allows attackers to steal GitHub PATs, perform SSRF against internal services, and control the content of dependency files. This issue was assigned CVE-2026-44971.

## Attack Chain

1. The attacker identifies a GuardDog instance scanning a repository URL they can influence.
2. The attacker crafts a malicious repository URL, embedding an attacker-controlled hostname (e.g., `http://github@127.0.0.1:18081/owner/repo`).
3. GuardDog's `ProjectScanner.scan_remote()` function receives the attacker-controlled URL.
4. The `scan_remote()` function performs a blind string replacement, transforming "github" to "raw.githubusercontent", resulting in a URL like `http://raw.githubusercontent@127.0.0.1:18081/owner/repo/main/requirements.txt`.
5. The `requests.get()` function interprets the URL as a request to `127.0.0.1:18081`.
6. GuardDog includes the configured `GH_TOKEN` as HTTP Basic Authentication credentials in the request's `Authorization` header.
7. The attacker's server receives the request, logging the `Authorization` header and requested path.
8. The attacker extracts the `GH_TOKEN` from the captured `Authorization` header or influences the dependency file content.

## Impact

Successful exploitation can lead to several critical consequences. The primary risk is the theft of the GitHub Personal Access Token (PAT) configured in the `GH_TOKEN` environment variable, allowing the attacker to impersonate the GuardDog instance and access its GitHub resources. Additionally, the SSRF vulnerability enables attacks against internal or localhost services reachable by the scanner, potentially compromising sensitive internal systems. Finally, the attacker can control the content of dependency files, leading to supply chain attacks.

## Recommendation

*   Deploy the Sigma rule `Detect GuardDog GH_TOKEN Exfiltration Attempt` to identify potential exfiltration attempts by monitoring network connections to non-GitHub hosts using the GitHub token.
*   Apply the suggested fix outlined in the advisory: parse the input URL, require `hostname == "github.com"`, validate the path shape, build the raw URL from parsed components instead of string replacement, and never send GitHub credentials to non-GitHub hosts.
*   Upgrade GuardDog to a version beyond 2.9.0 to remediate CVE-2026-44971.
