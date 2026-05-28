---
title: Gitea Unauthenticated Container Registry Access (CVE-2026-27771)
slug: 2026-05-gitea-vuln
description: A vulnerability in Gitea's built-in container registry (CVE-2026-27771) allows unauthenticated attackers to pull private container images, potentially exposing source code, secrets, and production infrastructure details, affecting over 30,000 deployments.
date: "2026-05-28T11:25:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - container registry
  - access control
  - cloud
  - git
vendors:
  - Gitea
products:
  - Gitea
  - Forgejo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.securityweek.com/gitea-vulnerability-exposed-30000-deployments-to-attacks/
  - CVE-2026-27771
rules:
  - title: Detect CVE-2026-27771 Exploitation Attempt - Unauthenticated Container Pull
    description: Detects attempts to pull container images from a Gitea instance without authentication, indicating potential exploitation of CVE-2026-27771.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-27771
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-27771 Exploitation Success - Anonymous Container Pull
    description: Detects successful anonymous pull of a container image, potentially indicating successful exploitation of CVE-2026-27771.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-27771
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, tracked as CVE-2026-27771, exists within the built-in container registry of the open-source Gitea Git service. This access control issue allows unauthenticated attackers to pull private container images without requiring any credentials or prior access. The vulnerability resided in Gitea's code for approximately four years before being patched in version 1.26.2. Forgejo, which shares the implementation, is also affected, and other Gitea-derived forks might be vulnerable. NoScope's analysis identified over 34,000 internet-facing Gitea instances, with roughly 93% (31,750) likely vulnerable. Around 4,000 were production systems on major cloud/VPS platforms, and 7,000 were running on the default port.

## Attack Chain

1.  Attacker identifies a vulnerable Gitea instance through Shodan or similar search engines.
2.  Attacker sends a standard, anonymous Docker/OCI pull request to the Gitea instance's container registry API.
3.  The Gitea instance, failing to enforce authentication, serves the requested private container image to the attacker.
4.  Attacker extracts the container image.
5.  Attacker analyzes the container image for sensitive information such as source code, credentials, and production infrastructure details.
6.  Attacker uses extracted credentials to gain unauthorized access to other systems or data.

## Impact

Successful exploitation of CVE-2026-27771 can expose sensitive information contained within private container images, including source code, secrets, and production infrastructure details. NoScope estimates that over 30,000 Gitea deployments were vulnerable, with a significant portion running production systems. This vulnerability allows an attacker to potentially gain unauthorized access to other systems by using exposed credentials, and can cause significant damage including data breaches and service disruption.

## Recommendation

*   Upgrade Gitea instances to version 1.26.2 or later to patch CVE-2026-27771.
*   Alternatively, change the configuration settings to require authentication for all content access as a temporary mitigation, understanding that this setting is not suitable for instances that intentionally expose some containers publicly.
