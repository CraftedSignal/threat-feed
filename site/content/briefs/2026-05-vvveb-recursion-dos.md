---
title: Vvveb Uncontrolled Recursion Denial of Service (CVE-2026-41935)
slug: 2026-05-vvveb-recursion-dos
description: Vvveb before version 1.0.8.3 is vulnerable to an uncontrolled recursion vulnerability in the admin controller dispatch cycle that allows a low-privilege attacker to cause denial of service by exhausting PHP memory.
date: "2026-05-14T15:17:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial of service
  - web application
  - recursion
vendors:
  - Vvveb
products:
  - Vvveb
  - Vvveb < 1.0.8.3
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-41935
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41935
  - https://github.com/givanz/Vvveb/commit/c766e84b479dcf1bd1f25a44e4b9c9fa450769c8
  - https://github.com/givanz/Vvveb/releases/tag/1.0.8.3
  - https://www.vulncheck.com/advisories/vvveb-uncontrolled-recursion-denial-of-service
rules:
  - title: Detect CVE-2026-41935 Exploitation Attempt - Multiple 403 Errors
    description: Detects CVE-2026-41935 exploitation attempt by monitoring for multiple 403 errors from the same source IP address within a short time frame, indicating potential access attempts to forbidden admin URLs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 1
---

Vvveb is susceptible to an uncontrolled recursion vulnerability (CVE-2026-41935) affecting versions prior to 1.0.8.3. The vulnerability lies within the admin controller dispatch cycle, specifically how `Base::init()` repeatedly invokes `permission()` on error handlers. This recursion occurs when a low-privilege account attempts to access forbidden admin URLs. By sending sustained requests, an attacker can exhaust the PHP memory on all workers, leading to a denial-of-service condition that impacts legitimate traffic. This vulnerability poses a significant risk to web applications using Vvveb, as even a low-privilege account can trigger a widespread outage.

## Attack Chain

1.  Attacker obtains a low-privilege account on the Vvveb application.
2.  Attacker identifies forbidden admin URLs (e.g., `/admin/config`).
3.  Attacker crafts HTTP requests targeting these forbidden admin URLs.
4.  The requests are sent to the Vvveb server.
5.  The server's admin controller dispatch cycle initiates.
6.  Due to insufficient permissions, `Base::init()` invokes `permission()` on error handlers.
7.  The error handler triggers a recursive call back to `permission()`, repeating infinitely.
8.  This uncontrolled recursion exhausts PHP memory limits on all workers, causing a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition affecting all users of the Vvveb application. While the vulnerability requires a low-privilege account, the resulting impact can be severe, potentially disrupting critical services and causing financial losses. The CVSS v3.1 base score is 7.1, indicating a high risk of exploitation and potential damage. The number of affected victims depends on the popularity and deployment size of the Vvveb instance.

## Recommendation

*   Upgrade Vvveb to version 1.0.8.3 or later to patch CVE-2026-41935; reference the advisory in the references section.
*   Deploy the Sigma rule "Detect CVE-2026-41935 Exploitation Attempt - Multiple 403 Errors" to identify potential exploitation attempts by monitoring web server logs for frequent 403 errors.
*   Monitor web server resource consumption (CPU, memory) for unexpected spikes, which could indicate a denial-of-service attack stemming from the uncontrolled recursion.
