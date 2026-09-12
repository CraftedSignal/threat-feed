---
title: 'CVE-2026-16482: Blind SQL Injection in rtMedia Plugin'
slug: 2026-09-rtmedia-sql-injection
description: The rtMedia for WordPress plugin is vulnerable to unauthenticated time-based blind SQL injection via the compare parameter, allowing sensitive database information extraction.
date: "2026-09-12T09:18:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rtcamp:rtmedia:*:*:*:*:*:wordpress:*:*
vendors:
  - rtCamp
products:
  - rtMedia for WordPress, BuddyPress and bbPress (<= 4.7.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is exploitable on any public page containing an rtMedia shortcode... allowing the nested 'compare' subvalue to reach the vulnerable sink without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-16482
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16482
rules:
  - title: Detect CVE-2026-16482 Exploitation - SQL Injection via rtMedia Parameter
    description: Detects exploitation attempts against CVE-2026-16482 by monitoring for suspicious nested parameter patterns in GET requests to WordPress pages.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade rtMedia plugin to a version > 4.7.11
      owner: IT Operations
      due: 48h
      evidence: Source states versions up to 4.7.11 are vulnerable
  hunt_leads:
    - lead: Search web logs for URLs containing 'compare['
      technique_id: T1190
      data_needed:
        - Web access logs (URI query string)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability relies on the 'compare' parameter being processed via insecure merges
  mitigation_plan:
    - priority: immediate
      action: Patch plugin
      owner: IT Operations
      addresses: CVE-2026-16482
      evidence: Plugin vulnerable <= 4.7.11
---

The rtMedia for WordPress, BuddyPress and bbPress plugin (versions 4.7.11 and earlier) contains a critical security flaw identified as CVE-2026-16482. This vulnerability is a time-based blind SQL injection caused by insufficient input escaping and lack of parameterized queries within the RTMediaQuery::query() method. Attackers can exploit this by injecting malicious SQL statements into the compare parameter. Because the plugin incorrectly merges the $_REQUEST array into the internal query while only validating top-level keys, an unauthenticated attacker can supply nested subvalues that reach the vulnerable SQL execution sink. This is specifically exploitable on any publicly accessible WordPress page containing an rtMedia shortcode, such as [rtmedia_gallery], when the rtmedia_shortcode GET parameter is present. Successful exploitation permits unauthorized access to sensitive database contents, posing a high risk to the confidentiality of stored data.

## Attack Chain

1. Attacker identifies a public-facing WordPress page containing an rtMedia shortcode (e.g., [rtmedia_gallery]).
2. Attacker crafts a malicious HTTP GET request targeting the identified page.
3. Attacker appends the rtmedia_shortcode parameter to the URL to trigger the vulnerable code path.
4. Attacker injects a malicious payload into the compare parameter, formatted as a nested subvalue (e.g., compare[field]=value).
5. The server-side RTMediaQuery::query() function receives the request and improperly merges the input into a database query.
6. The backend SQL database processes the injected time-based command (e.g., SLEEP() or BENCHMARK()).
7. Attacker observes the differential in HTTP response time to confirm successful injection and exfiltrate data character-by-character.

## Impact

Successful exploitation allows unauthenticated remote attackers to perform unauthorized database queries. This can lead to the full extraction of sensitive WordPress site data, including user credentials, configuration details, and private content, directly impacting the confidentiality of the affected organization.

## Recommendation

* Update the rtMedia for WordPress, BuddyPress and bbPress plugin to the latest patched version immediately.
* Use the provided Sigma rule to monitor web server logs for suspicious parameter patterns associated with this vulnerability.
* Implement a Web Application Firewall (WAF) rule to inspect and block incoming GET requests containing recursive or nested parameter keys associated with SQL injection attempts.
