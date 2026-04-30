---
title: Synway SMG Gateway Management Software Unauthenticated OS Command Injection
slug: 2026-05-synway-smg-rce
description: Synway SMG Gateway Management Management Software is vulnerable to unauthenticated OS command injection via crafted POST requests to the RADIUS configuration endpoint, leading to remote code execution.
date: "2026-04-30T17:16:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - network
vendors:
  - Synway
products:
  - SMG Gateway Management Software
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2025-71284
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71284
rules:
  - title: Synway SMG Gateway Radius Command Injection Attempt
    description: Detects potential OS command injection attempts via POST requests to the Synway SMG Gateway RADIUS configuration endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Synway SMG Gateway Radius Command Injection UserAgent Curl
    description: Detects potential OS command injection attempts via POST requests to the Synway SMG Gateway RADIUS configuration endpoint with UserAgent as Curl
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
---

Synway SMG Gateway Management Software is susceptible to an OS command injection vulnerability (CVE-2025-71284) within the RADIUS configuration endpoint. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted POST request to `/en/9-2radius.php`. The vulnerability lies in the improper sanitization of the `radius_address` POST parameter, which is directly incorporated into a `sed` command. The Shadowserver Foundation observed the first exploitation evidence on 2025-07-11 (UTC). Successful exploitation allows the attacker to execute arbitrary shell commands on the affected system, potentially compromising the entire gateway. This vulnerability poses a significant risk to organizations using the Synway SMG Gateway, as it enables unauthenticated remote code execution.

## Attack Chain

1.  An unauthenticated attacker identifies a Synway SMG Gateway Management Software instance exposed to the network.
2.  The attacker crafts a malicious POST request targeting the `/en/9-2radius.php` endpoint.
3.  The POST request includes parameters such as `radius_address`, `radius_address2`, `shared_secret2`, `source_ip`, `timeout`, or `retry` along with `save=1` and `enable_radius=1`.
4.  The `radius_address` parameter contains an OS command injection payload.
5.  The application improperly sanitizes the `radius_address` parameter and incorporates it into a `sed` command.
6.  The injected command is executed by the operating system, granting the attacker arbitrary code execution privileges.
7.  The attacker establishes a reverse shell to maintain persistence and expand their foothold.
8.  The attacker pivots within the network, gaining access to sensitive data or systems, and potentially establishing a long-term presence.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary commands on the Synway SMG Gateway. This could lead to complete system compromise, data theft, disruption of services, and further propagation of attacks within the network. Given the high CVSS score (9.8), this vulnerability represents a critical threat. The number of affected systems and organizations is currently unknown.

## Recommendation

*   Deploy the Sigma rule "Synway SMG Gateway Radius Command Injection Attempt" to your SIEM to detect exploitation attempts based on suspicious POST requests to the vulnerable endpoint.
*   Apply input validation and sanitization to the `radius_address`, `radius_address2`, `shared_secret2`, `source_ip`, `timeout`, and `retry` parameters in the RADIUS configuration endpoint.
*   Monitor web server logs for POST requests to `/en/9-2radius.php` containing suspicious characters or command sequences indicative of command injection attacks to activate the "Synway SMG Gateway Radius Command Injection Attempt" rule.
