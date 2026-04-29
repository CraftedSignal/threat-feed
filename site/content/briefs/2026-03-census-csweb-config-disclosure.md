---
title: Census CSWeb 8.0.1 Configuration File Disclosure Vulnerability
slug: 2026-03-census-csweb-config-disclosure
description: Census CSWeb 8.0.1 is vulnerable to unauthenticated remote configuration file disclosure via HTTP requests to the `/app/config` path, potentially exposing sensitive secrets; fixed in 8.1.0 alpha.
date: "2026-03-24T14:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2025-60949
  - information-disclosure
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-60949
  - https://github.com/csprousers/csweb/commit/eba0b59a243390a1a4f9524cce6dbc0314bf0d91
  - https://github.com/hx381/cspro-exploits
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-082-01.json
rules:
  - title: Detect Unauthenticated Access to Configuration Files
    description: Detects unauthenticated HTTP GET requests to the /app/config directory, indicative of potential CVE-2025-60949 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed Accesses to Configuration Files
    description: Detects a high number of failed access attempts to the /app/config directory from a single source IP, possibly indicating an automated exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Census CSWeb version 8.0.1 is susceptible to a critical vulnerability (CVE-2025-60949) that allows unauthenticated remote attackers to access sensitive configuration files. This exposure occurs because the `/app/config` directory is reachable via HTTP in certain deployments. By sending a specially crafted request to this path, an attacker can potentially obtain sensitive information, such as API keys, database credentials, and other secrets stored within the configuration files. This vulnerability was publicly disclosed on March 23, 2026, and a fix is available in version 8.1.0 alpha. Exploitation of this vulnerability can lead to significant data breaches and compromise of the affected system. Defenders should prioritize identifying and patching vulnerable instances.

## Attack Chain

1.  The attacker identifies a target running Census CSWeb 8.0.1.
2.  The attacker sends an HTTP GET request to `/app/config` directory or specific files within that directory.
3.  The vulnerable server processes the request without proper authentication or access controls.
4.  The server responds with the contents of the configuration files, potentially containing sensitive information.
5.  The attacker parses the configuration files to extract sensitive data, such as API keys, database credentials, or internal IP addresses.
6.  The attacker uses the extracted credentials to gain unauthorized access to databases, APIs, or other systems.
7.  The attacker escalates privileges within the compromised systems.

## Impact

Successful exploitation of CVE-2025-60949 can lead to the exposure of sensitive information, including API keys, database credentials, and other secrets. This can allow attackers to gain unauthorized access to critical systems, leading to data breaches, financial loss, and reputational damage. The vulnerability affects all deployments of Census CSWeb 8.0.1 where the `/app/config` directory is exposed via HTTP.

## Recommendation

*   Upgrade to Census CSWeb version 8.1.0 alpha or later to patch CVE-2025-60949.
*   Implement access controls to restrict access to the `/app/config` directory to authorized personnel only.
*   Deploy the Sigma rule "Detect Unauthenticated Access to Configuration Files" to identify potential exploitation attempts.
*   Monitor web server logs for requests to `/app/config` to detect unauthorized access attempts.
