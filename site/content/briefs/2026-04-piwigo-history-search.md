---
title: Piwigo Unauthenticated History Search Access
slug: 2026-04-piwigo-history-search
description: Piwigo versions prior to 16.3.0 expose the full browsing history of gallery visitors to unauthenticated users via the pwg.history.search API method due to a missing authorization check.
date: "2026-04-03T22:16:25Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - piwigo
  - vulnerability
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
cves:
  - id: CVE-2026-27833
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27833
  - https://github.com/Piwigo/Piwigo/commit/d05c16561ce3692ca922199f8c8d7b1a45893f1c
  - https://github.com/Piwigo/Piwigo/security/advisories/GHSA-397m-gfhm-pmg2
  - https://piwigo.org/release-16.3.0
iocs:
  - type: email
    value: email protected
ioc_counts:
  email: 1
rules:
  - title: Detect Piwigo History Search Access
    description: Detects unauthenticated access to the pwg.history.search API endpoint in Piwigo, indicating potential CVE-2026-27833 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.001
    data_sources:
      - webserver
      - linux
  - title: Detect Piwigo API Access Attempt
    description: Detects access to the Piwigo API based on cs-uri-query
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1592.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Piwigo, an open-source photo gallery application, contains a vulnerability (CVE-2026-27833) affecting versions prior to 16.3.0. The vulnerability lies within the `pwg.history.search` API method, which lacks an `admin_only` access control. This oversight allows unauthenticated users to query and retrieve the browsing history of all gallery visitors. An attacker can leverage this flaw to gain insights into user behavior, potentially exposing sensitive information about their interests and activities within the photo gallery. Piwigo version 16.3.0 addresses this vulnerability by implementing the necessary authorization check.

## Attack Chain

1.  An unauthenticated attacker identifies a Piwigo instance running a version prior to 16.3.0.
2.  The attacker crafts a malicious HTTP request targeting the `pwg.history.search` API endpoint.
3.  The attacker sends the crafted HTTP request to the vulnerable Piwigo server.
4.  The Piwigo server, lacking proper authorization checks, processes the request without authentication.
5.  The server retrieves the browsing history of all gallery visitors from the database.
6.  The server returns the browsing history data in the HTTP response to the attacker.
7.  The attacker parses the response and analyzes the browsing history data to identify user activities and interests.

## Impact

Successful exploitation of CVE-2026-27833 allows unauthenticated attackers to access sensitive user browsing history within a Piwigo photo gallery. This can lead to a privacy breach, potentially exposing user interests, activities, and even personal information gleaned from their browsing patterns. The impact is limited to information disclosure as the attacker cannot modify data, but the privacy implications can be significant for users of affected Piwigo installations.

## Recommendation

*   Upgrade all Piwigo installations to version 16.3.0 or later to patch CVE-2026-27833.
*   Monitor web server logs for requests to the `pwg.history.search` API endpoint, especially those lacking authentication, to detect potential exploitation attempts. Deploy the Sigma rule `Detect Piwigo History Search Access` to identify suspicious activity.
*   Implement a Web Application Firewall (WAF) rule to block unauthorized access to the `pwg.history.search` API endpoint.
