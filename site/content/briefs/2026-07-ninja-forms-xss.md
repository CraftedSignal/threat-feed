---
title: Critical Unauthenticated Stored XSS in Ninja Forms WordPress Plugin (CVE-2026-65048)
slug: 2026-07-ninja-forms-xss
description: A critical unauthenticated stored cross-site scripting (XSS) vulnerability (CVE-2026-65048) in the Ninja Forms plugin for WordPress allows attackers to inject malicious script payloads via crafted form submissions, leading to session-cookie theft, administrator account creation, and arbitrary content modification when an administrator views the submission.
date: "2026-07-21T15:19:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - xss
  - plugin
  - web-application
  - cve
vendors:
  - Ninja Forms
  - WordPress
products:
  - Ninja Forms plugin 3.10.4-3.14.9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can submit a public form with a crafted repeater child key containing malicious script payloads
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: malicious script payloads, which execute in an administrator's browser when viewing submissions in the WordPress admin panel
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: enabling session-cookie theft
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: ""
    evidence: creation of administrator accounts
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: ""
    evidence: creation of administrator accounts
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: ""
    evidence: arbitrary modification of site content
    confidence_band: high
cves:
  - id: CVE-2026-65048
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65048
rules:
  - title: Detects CVE-2026-65048 Exploitation - Ninja Forms XSS Injection
    description: Detects CVE-2026-65048 exploitation - HTTP POST requests likely targeting Ninja Forms submission endpoints containing common XSS script patterns in the URI query or request body, indicative of an attempt to inject malicious content.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical unauthenticated stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-65048, affects the Ninja Forms plugin for WordPress versions 3.10.4 through 3.14.9. This flaw lies within the plugin's Repeatable Fieldset feature, specifically in the `parseSubmissionIndex()` function which fails to validate numeric input, allowing arbitrary strings as submission indexes. Subsequently, the `admin_form_element()` function directly interpolates these unescaped, attacker-controlled strings into HTML when administrators view form submissions. An unauthenticated attacker can exploit this by submitting a public Ninja Forms form with a specially crafted repeater child key containing malicious JavaScript. When a site administrator accesses the WordPress admin panel to review the compromised form submission, the embedded script executes in their browser. This allows the attacker to achieve severe outcomes such as stealing session cookies, creating new administrative accounts, installing malicious plugins, or arbitrarily altering website content, posing a significant risk to the integrity and security of affected WordPress installations.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the vulnerable Ninja Forms plugin (versions 3.10.4-3.14.9).
2. The attacker accesses a public-facing Ninja Forms form that utilizes a Repeatable Fieldset feature.
3. The attacker crafts an HTTP POST request to submit the form, embedding a malicious JavaScript payload within a repeater child key field as an arbitrary string.
4. The server-side `parseSubmissionIndex()` function in the Ninja Forms plugin processes this submission, accepting the unvalidated, arbitrary string as a submission index without proper numeric validation.
5. When an administrator navigates to the WordPress admin panel to view the submitted form data, the `admin_form_element()` function retrieves and interpolates the unescaped, malicious string directly into the HTML of the submission view.
6. The administrator's web browser renders the HTML, executing the embedded malicious JavaScript payload.
7. The executed script can steal the administrator's session cookies, create new administrator accounts, install malicious plugins, or arbitrarily modify the website's content.

## Impact

Successful exploitation of CVE-2026-65048 by an unauthenticated attacker leads to significant security compromises. The primary impact includes session-cookie theft, which can grant an attacker unauthorized access to the administrator's active session, effectively bypassing authentication. Furthermore, the attacker can leverage the XSS to create new administrator accounts, granting persistent backdoor access, install malicious plugins to inject malware or backdoors, or arbitrarily modify existing website content, leading to defacement, data manipulation, or further compromise of site visitors. This high-severity vulnerability poses a critical risk to the confidentiality, integrity, and availability of affected WordPress installations.

## Recommendation

* Patch CVE-2026-65048 immediately by updating the Ninja Forms plugin to a version greater than 3.14.9.
* Deploy the Sigma rule "Detects CVE-2026-65048 Exploitation - Ninja Forms XSS Injection" to your SIEM and monitor webserver logs for suspicious form submissions containing XSS payloads.
* Enable comprehensive web server logging, ensuring that HTTP request bodies (`c-bytes`) are captured, as the malicious payload may reside within form submission data.
