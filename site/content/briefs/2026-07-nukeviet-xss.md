---
title: NukeViet Unauthenticated Reflected XSS in Comment Module
slug: 2026-07-nukeviet-xss
description: An unauthenticated reflected Cross-Site Scripting (XSS) vulnerability in the NukeViet Comment module allows threat actors to execute arbitrary client-side script due to improper input sanitization and rendering of the base64-encoded `status_comment` URL parameter, compounded by a static anti-forgery `checkss` token that permits session-independent attack delivery for credential theft.
date: "2026-07-13T17:24:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nukeviet
  - xss
  - web-vulnerability
  - reflected-xss
  - credential-theft
  - vulnerability-exploitation
vendors:
  - NukeViet
products:
  - NukeViet CMS (< 4.5.09)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitable remotely via crafted URL
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: JavaScript executes in victim's browser
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: ""
    evidence: Attacker delivers the following URL to the victim
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: access to cookies, session storage, and the ability to make authenticated requests
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mxpf-qgg6-v3ff
rules:
  - title: Detects CVE-2026-48118 Exploitation - NukeViet XSS via status_comment
    description: Detects CVE-2026-48118 exploitation - HTTP GET/POST requests to NukeViet comment module with an encoded status_comment parameter, indicating a reflected XSS attempt. This rule targets the specific parameters and a long base64-like string in status_comment.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical reflected Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-48118, has been identified in the NukeViet Comment module versions prior to 4.5.09. This flaw allows unauthenticated attackers to execute arbitrary HTML and JavaScript within a victim's browser context. The vulnerability arises from two issues: first, the `status_comment` URL parameter's base64-encoded content is improperly sanitized and rendered unescaped, allowing malicious scripts to bypass `strip_tags()` filtering. Second, the `checkss` anti-forgery token, intended to prevent CSRF, is derived from a static, site-wide constant (`NV_CACHE_PREFIX`) rather than a session-bound value. This enables attackers to obtain a valid token from any page and reuse it in a crafted URL targeting other users. The combination facilitates highly effective client-side attacks, including credential theft via phishing overlays, with confirmed in-the-wild impact.

## Attack Chain

1. An attacker identifies a vulnerable NukeViet instance running the Comment module (versions prior to 4.5.09).
2. The attacker navigates to any public article or page containing a comment block on the target NukeViet site.
3. The attacker extracts the static, session-independent `checkss` anti-forgery token from the page's HTML source.
4. The attacker crafts a malicious HTML/JavaScript payload designed for client-side execution (e.g., a credential phishing overlay).
5. The attacker base64-encodes the malicious payload to bypass initial `strip_tags()` sanitization.
6. The attacker constructs a malicious URL incorporating the extracted `checkss` token and the base64-encoded payload in the `status_comment` parameter, along with other required parameters (`nv=comment`, `comment_load=1`, `module`, `area`, `id`, `allowed`).
7. The attacker delivers this crafted URL to a victim, typically via a phishing email or instant message.
8. When the victim opens the malicious URL, the decoded HTML/JavaScript executes within their browser under the legitimate NukeViet site's origin, enabling actions like cookie theft, session hijacking, or displaying phishing forms to capture credentials.

## Impact

The successful exploitation of CVE-2026-48118 allows unauthenticated attackers to execute arbitrary client-side scripts, leading to significant confidentiality and integrity impacts. Observed attacks include the deployment of phishing overlay forms capable of capturing plaintext credentials, which are then transmitted to attacker-controlled servers. Victims interacting with the compromised page may have their session cookies stolen, sensitive information exfiltrated from the DOM, or be subjected to further client-side attacks. Given the unauthenticated nature of the vulnerability and the low attack complexity, a wide range of NukeViet users are at risk, particularly those visiting attacker-crafted links.

## Recommendation

* Patch CVE-2026-48118 immediately by updating NukeViet CMS to version 4.5.09 or higher. This addresses both the XSS sink and the weak `checkss` token.
* Deploy the Sigma rule below to your SIEM to detect attempts to exploit the `status_comment` parameter via webserver logs.
* Ensure webserver logs (category `webserver`) are configured to capture full URI query strings (`cs-uri-query`) for effective detection of this attack pattern.
