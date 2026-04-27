---
title: Piwigo Unauthenticated History Search Access
slug: 2026-04-piwigo-history-search
description: Piwigo versions prior to 16.3.0 expose the full browsing history of gallery visitors to unauthenticated users via the pwg.history.search API method due to a missing authorization check.
date: "2026-04-03T22:16:25Z"
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

Piwigo, an open-source photo gallery application, contains a vulnerability (CVE-2026-27833) affecting versions prior to 16.3.0. The vulnerability lies within the `pwg.history.search` API method, which lacks an `admin_only` access control. This oversight allows unauthenticated users to query and retrieve the browsing history of all gallery visitors. An attacker can leverage this flaw to gain insights into user behavior, potentially exposing sensitive information about their interests and…
