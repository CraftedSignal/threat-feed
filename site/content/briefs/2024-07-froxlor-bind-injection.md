---
title: Froxlor BIND Zone File Injection Vulnerability
slug: 2024-07-froxlor-bind-injection
description: Froxlor versions 2.3.4 and earlier are vulnerable to BIND zone file injection, where an attacker can inject newlines and BIND zone file directives via the DomainZones API, potentially leading to information disclosure, DNS service disruption, and zone data manipulation.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - froxlor
  - bind
  - zone-file-injection
  - dns
vendors:
  - Froxlor
products:
  - Froxlor
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-x6w6-2xwp-3jh6
rules:
  - title: Detect Froxlor BIND Zone File Injection Attempts
    description: Detects suspicious API requests to Froxlor's DomainZones.add endpoint with potential BIND zone file injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Newlines in Froxlor DNS Content
    description: Detects newline characters in DNS content submitted to the Froxlor API, which could indicate a zone file injection attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Froxlor, a server management panel, is vulnerable to a BIND zone file injection vulnerability (CVE-2026-30932) affecting versions 2.3.4 and earlier. This vulnerability exists within the `DomainZones.add` API endpoint, accessible to customers with DNS enabled. Due to insufficient validation of the `content` field for specific DNS record types (LOC, RP, SSHFP, TLSA), attackers can inject arbitrary BIND zone file directives. This injection occurs because the `content` field is not properly sanitized, as highlighted by a TODO comment in the source code. Successful exploitation can lead to unauthorized file access, DNS service disruptions, and manipulation of zone data. This vulnerability poses a significant risk to Froxlor users as it allows malicious actors to compromise the integrity and availability of DNS services.

## Attack Chain

1. Attacker gains access to a Froxlor customer account with DNS management enabled.
2. The attacker crafts a malicious API request to the `DomainZones.add` endpoint.
3. The API request includes a DNS record type (LOC, RP, SSHFP, TLSA) and a `content` field containing injected BIND directives, such as `$INCLUDE /etc/passwd`.
4. The Froxlor application writes the unsanitized content directly into the BIND zone file via `DnsEntry::__toString()`.
5. The DNS rebuild cron job runs, processing the modified zone file.
6. BIND attempts to parse the injected directives, such as including `/etc/passwd` as zone data.
7. The attacker uses the `DomainZones.get` API or web UI to view the zone file and extract sensitive information or confirms service disruption.
8. Successful exploitation leads to information disclosure, DNS service disruption, or zone data manipulation.

## Impact

Successful exploitation of this vulnerability can have significant consequences. Information disclosure allows attackers to read world-readable files on the server, potentially exposing sensitive data. DNS service disruption can occur if the injected content causes BIND to fail to load the zone, leading to downtime for affected domains. Furthermore, attackers can manipulate zone data by injecting arbitrary DNS records, potentially redirecting traffic or causing other malicious activities. The vulnerability affects Froxlor versions 2.3.4 and earlier.

## Recommendation

*   Apply the patch or upgrade to a version of Froxlor greater than 2.3.4 to remediate CVE-2026-30932, which addresses the input validation issue.
*   Deploy the Sigma rule "Detect Froxlor BIND Zone File Injection Attempts" to identify suspicious API requests targeting the `DomainZones.add` endpoint (rules).
*   Monitor web server logs for POST requests to `/api.php` with `command: DomainZones.add` and suspicious characters or BIND directives in the `params` field to detect exploitation attempts (webserver).
