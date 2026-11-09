---
brief_id: brief-2026-10-roundcube-imap-injection
event_id: brief-2026-10-roundcube-imap-injection
revision: 2
activity_at: "2026-11-09T01:11:49Z"
revision_history:
  - revision: 2
    at: "2026-11-09T01:11:49Z"
    checksum: sha256:d4d84d1dde42d5a67d6a43a5ca2ed6041bf1e6c83f6965365b28acc3ae321ef1
    summary: poc_available
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=3CFE4ACC-CDC0-5571-A68E-16091798B40E&utm_source=rss&utm_medium=rss
title: IMAP Command Injection in Roundcube Webmail
slug: 2026-10-roundcube-imap-injection
description: Roundcube Webmail versions prior to 1.6.20 and 1.7.5 are vulnerable to IMAP command injection via CRLF sequences in the _uid parameter, allowing authenticated remote attackers to execute arbitrary IMAP commands.
date: "2026-10-20T06:34:38Z"
lastmod: "2026-11-09T01:10:31Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Brief verified against NVD. Sigma rule logic based on provided vulnerability details.
cpes:
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=3CFE4ACC-CDC0-5571-A68E-16091798B40E&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - imap
  - injection
vendors:
  - Roundcube
products:
  - Webmail (< 1.6.20, 1.7.x < 1.7.5)
  - Webmail (< 1.7.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A remote authenticated attacker can exploit this via CRLF sequences... to execute arbitrary IMAP commands.
    confidence_band: high
cves:
  - id: CVE-2026-113386
    cvss: 7.1
    kev_status: unknown
  - id: CVE-2026-114727
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113386
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114727
  - https://sploitus.com/exploit?id=3CFE4ACC-CDC0-5571-A68E-16091798B40E&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-113386 Exploitation - IMAP Injection via Roundcube
    description: Detects exploitation of CVE-2026-113386 by identifying CRLF injection patterns within the _uid parameter in Roundcube Webmail requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Roundcube Webmail to 1.6.20 or 1.7.5
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-113386 advisory
  hunt_leads:
    - lead: Inspect web logs for _uid parameter containing CRLF characters
      technique_id: T1059
      data_needed:
        - web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary IMAP command execution
  mitigation_plan:
    - priority: immediate
      action: Apply security patch to Roundcube instances
      owner: IT Operations
      addresses: CVE-2026-113386
      evidence: NVD report
updates:
  - at: "2026-10-22T06:01:23Z"
    level: L2
    summary: added coverage for Webmail (< 1.6.20, 1.7.x < 1.7.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114727
  - at: "2026-11-09T01:10:31Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=3CFE4ACC-CDC0-5571-A68E-16091798B40E&utm_source=rss&utm_medium=rss
---

Roundcube Webmail versions before 1.6.20 and 1.7.x before 1.7.5 contain a vulnerability that permits IMAP command injection. This issue occurs due to improper sanitization of user-supplied input within the _uid parameter when processed by the application's mail/headers and mail/viewsource actions. A remote authenticated attacker can leverage this flaw by injecting Carriage Return Line Feed (CRLF) sequences into the targeted parameter. 

Successful exploitation allows the attacker to bypass application logic and send arbitrary commands to the IMAP server associated with the webmail instance. This may lead to unauthorized access to email data, manipulation of mailbox structures, or potential exposure of sensitive information stored on the backend mail server. Security teams should prioritize patching affected instances to the specified secure versions to mitigate this risk.

## Attack Chain

1. The attacker gains authenticated access to a vulnerable Roundcube Webmail instance.
2. The attacker identifies the mail/headers or mail/viewsource actions as endpoints that process the _uid parameter.
3. The attacker crafts an HTTP request targeting one of these actions.
4. The attacker injects malicious CRLF sequences into the _uid parameter string.
5. The application fails to sanitize the input, passing the injected payload to the backend IMAP communication layer.
6. The IMAP server interprets the injected CRLF sequences, executing the attacker-supplied IMAP commands in the context of the user's session.
7. The attacker exfiltrates or manipulates mailbox data through the unauthorized IMAP operations.

## Impact

The vulnerability allows an authenticated attacker to execute arbitrary commands against the backend IMAP server. This can result in unauthorized access to private emails, modification of mailbox contents, and a breach of data confidentiality for users within the organization. While this requires authentication, the impact is severe for multi-user email environments where an attacker might compromise one account to gain unauthorized access to mail data or perform lateral movement within the mail infrastructure.

## Recommendation

* Patch Roundcube Webmail to version 1.6.20 or 1.7.5 or later immediately.
* Monitor web server access logs for anomalous HTTP requests to the mail/headers and mail/viewsource endpoints containing CRLF characters or abnormal IMAP command syntax in the _uid parameter.
* Review web application firewall (WAF) logs for blocked requests attempting to inject line-breaking characters into URL query parameters.
