---
title: Cockpit Remote Login Command Injection (CVE-2026-4631)
slug: 2024-01-30-cockpit-rce
description: CVE-2026-4631 allows remote attackers to execute arbitrary code on a Cockpit host by injecting malicious SSH options via a crafted HTTP request to the login endpoint due to insufficient input validation of user-supplied hostnames and usernames.
date: "2024-01-30T12:00:00Z"
lastmod: "2026-07-12T09:01:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B4423B41-80EB-54A0-8CBA-39356C37524C&utm_source=rss&utm_medium=rss
tags:
  - cockpit
  - rce
  - command-injection
  - CVE-2026-4631
  - linux
vendors:
  - Cockpit
products:
  - Cockpit (327 – 359)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
cves:
  - id: CVE-2026-4631
    cvss: 9.8
    epss: 0.142
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4631
  - https://sploitus.com/exploit?id=B4423B41-80EB-54A0-8CBA-39356C37524C&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=B4423B41-80EB-54A0-8CBA-39356C37524C
  - type: url
    value: https://github.com/ExDev994/CVE-2026-4631-cockpit-RCE.git
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious Cockpit Login Attempts
    description: Detects attempts to exploit CVE-2026-4631 by identifying unusual characters or commands in the cs-uri-query field of web server logs when accessing the /cockpit/login endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SSH Options in Cockpit Login
    description: Detects attempts to use dangerous SSH options like ProxyCommand in Cockpit logins, potentially indicating CVE-2026-4631 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-07-12T09:01:04Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=B4423B41-80EB-54A0-8CBA-39356C37524C&utm_source=rss&utm_medium=rss
---

Cockpit is a web-based interface for system administration. CVE-2026-4631 affects the remote login functionality in Cockpit. Specifically, the vulnerability exists because the application fails to properly sanitize or validate user-supplied input for hostnames and usernames when initiating SSH connections. This allows an attacker with network access to the Cockpit web service to inject arbitrary SSH options or shell commands into the SSH command executed by the Cockpit server. No authentication is required to exploit this vulnerability, as the injection occurs before any credential verification. The vulnerability was published on 2026-04-07 and has a CVSS v3.1 base score of 9.8, indicating its critical severity. Successful exploitation leads to arbitrary code execution on the Cockpit host.

## Attack Chain

1.  Attacker identifies a Cockpit instance accessible over the network.
2.  Attacker crafts a malicious HTTP request to the Cockpit login endpoint (typically `/cockpit/login`).
3.  The crafted request includes a hostname or username containing injected SSH options or shell commands (e.g., `-o ProxyCommand=evil.sh`).
4.  Cockpit's backend processes the request and constructs an SSH command using the unsanitized input.
5.  The injected SSH options or commands are executed by the `ssh` command on the Cockpit server.
6.  If the injected content is a shell command, it executes with the privileges of the Cockpit process.
7.  The attacker gains arbitrary code execution on the Cockpit host.
8.  The attacker can then perform further actions such as installing malware, creating new user accounts, or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-4631 allows an unauthenticated attacker to achieve remote code execution on the Cockpit host. The impact is severe, potentially leading to full system compromise. Given the role of Cockpit in system administration, a compromised host could allow attackers to gain control over other systems managed through the Cockpit interface. The number of victims will depend on the prevalence of vulnerable Cockpit instances exposed to the network.

## Recommendation

*   Apply the patch or upgrade to a version of Cockpit that addresses CVE-2026-4631 to remediate the vulnerability.
*   Deploy the Sigma rule `Detect Suspicious Cockpit Login Attempts` to identify exploitation attempts by monitoring for specific HTTP request patterns.
*   Implement strict input validation and sanitization on the Cockpit login endpoint to prevent command injection.
*   Monitor webserver logs for unusual requests to the `/cockpit/login` endpoint (logsource: webserver).
*   Review and harden the configuration of SSH clients used by Cockpit.
