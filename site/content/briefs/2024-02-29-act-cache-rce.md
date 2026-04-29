---
title: act Project Cache Poisoning Vulnerability Leads to Potential RCE
slug: 2024-02-29-act-cache-rce
description: A vulnerability in versions prior to 0.2.86 of the act project allows remote attackers to create arbitrary caches, potentially leading to remote code execution within Docker containers by poisoning predicted cache keys.
date: "2026-03-31T03:15:58Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - act
  - cache-poisoning
  - rce
  - github-actions
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-34042
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34042
rules:
  - title: Detect act Cache Server Exposed on All Interfaces
    description: Detects instances of the act cache server listening on all interfaces (0.0.0.0), which is vulnerable in versions prior to 0.2.86.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious File Creation in Docker after act Execution
    description: Detects suspicious file creation activity within Docker containers shortly after act execution, potentially indicating code execution from a poisoned cache.
    platform: sigma
    severity: high
    tactics:
      - execution
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `act` project, designed for local execution of GitHub Actions workflows, contains a critical vulnerability affecting versions prior to 0.2.86. The built-in actions/cache server, intended for local caching, inadvertently listens for connections on all network interfaces. This exposure allows any attacker capable of reaching the server, including those on the internet, to create caches with arbitrary keys and retrieve existing cache data. By predicting the cache keys used by local actions, an attacker can inject malicious content into the cache, paving the way for arbitrary remote code execution within the Docker container used by `act`. This vulnerability was addressed in version 0.2.86 of `act`. The CVSS v3.1 base score is 8.2, indicating a high severity threat.

## Attack Chain

1. The attacker identifies a vulnerable `act` instance running a version prior to 0.2.86 with its cache server exposed on all interfaces.
2. The attacker probes the exposed `act` cache server to determine accessible endpoints and version information.
3. The attacker analyzes common GitHub Actions workflows and identifies predictable cache keys.
4. The attacker crafts a malicious cache archive containing payloads designed for remote code execution.
5. The attacker uploads the malicious cache archive to the vulnerable `act` instance using the predicted cache key.
6. A legitimate user triggers a local GitHub Actions workflow using `act`.
7. The `act` instance retrieves the attacker's malicious cache archive instead of the expected legitimate cache.
8. The malicious payload within the cache is executed within the Docker container, leading to remote code execution on the host system running `act`.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary remote code execution on the host system running the vulnerable version of `act`. This can lead to complete system compromise, data theft, and further lateral movement within the network. The vulnerability affects any user running a version of `act` prior to 0.2.86 with the cache server exposed. While the number of directly affected users is unknown, the potential impact on development environments and CI/CD pipelines is significant.

## Recommendation

*   Upgrade to version 0.2.86 or later of the `act` project to remediate the vulnerability (CVE-2026-34042).
*   Implement network access controls to restrict access to the `act` cache server to only trusted networks and hosts.
*   Monitor network connections to the `act` cache server for unexpected or unauthorized access.
*   Enable process monitoring on systems running `act` to detect potentially malicious processes spawned from Docker containers.
