---
title: Unauthenticated Stripe Checkout Manipulation in Ghost
slug: 2026-10-ghost-stripe-vuln
description: A vulnerability in Ghost versions 5.2.0 through 6.61.9 allows unauthenticated remote attackers to manipulate Stripe Checkout flows to modify member records and inject malicious content into newsletters.
date: "2026-10-01T12:42:24Z"
lastmod: "2026-10-02T12:24:01Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:ghost:ghost:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - application-security
  - enumeration
  - api-security
  - remote-code-execution
  - ghost
  - vulnerability
  - cms
vendors:
  - Ghost
products:
  - Ghost (5.2.0 - 6.61.9)
  - Ghost (< 6.62.0)
  - Ghost (2.10.0 - 6.62.x)
  - Ghost (5.8.0 - 6.33.9)
  - Ghost (0.5.3 - < 6.50.0)
  - Ghost (6.22.1 <= version < 6.64.0)
  - Ghost (6.10.3 to < 6.64.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Ghost versions before 6.62.0 contain an authentication bypass vulnerability that allows suspended staff users to reactivate their accounts.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can observe discrepancies in API metadata responses to enumerate staff members and extract sensitive information without authentication.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers with content publishing privileges can craft malicious pages that, when visited by active staff users, enable account takeover through improper input validation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This vulnerability allows an authenticated attacker... to perform an account takeover of staff users.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with limited privileges can inject unescaped content that is rendered as script in the published page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The vulnerability allows for Stored Cross-Site Scripting (XSS) attacks... enabling the injection of malicious scripts that execute in the context of a staff user's admin session.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.004
    technique_name: 'Server Software Component: Web Shell'
    evidence: Attackers can upload script-bearing files to the site's domain to compromise other staff users' admin sessions.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Ghost from 6.10.3 before 6.64.0 contains a remote code execution vulnerability that allows authenticated administrators to run code by abusing theme translation file loading.
    confidence_band: high
cves:
  - id: CVE-2026-103266
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103266
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103268
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103272
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103278
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103292
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104411
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104418
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Ghost to 6.62.0 or later to patch CVE-2026-103266
      owner: IT Operations
      due: 48h
      evidence: Source states Ghost versions prior to 6.62.0 allow a remote attacker to abuse Stripe Checkout flow
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ghost to 6.62.0
      owner: IT Operations
      addresses: CVE-2026-103266
      evidence: NVD vulnerability details confirm 6.62.0 as the fixed version
updates:
  - at: "2026-10-01T12:44:15Z"
    level: L2
    summary: added coverage for Ghost (2.10.0 - 6.62.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103272
  - at: "2026-10-01T12:44:25Z"
    level: L2
    summary: added coverage for Ghost (5.8.0 - 6.33.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103278
  - at: "2026-10-01T12:44:39Z"
    level: L2
    summary: added coverage for Ghost (0.5.3 - < 6.50.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103292
  - at: "2026-10-02T12:23:44Z"
    level: L2
    summary: added coverage for Ghost (6.22.1 <= version < 6.64.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104411
  - at: "2026-10-02T12:24:01Z"
    level: L2
    summary: added coverage for Ghost (6.10.3 to < 6.64.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104418
---

Ghost versions 5.2.0 through 6.61.9 are susceptible to an unauthenticated vulnerability within the Stripe Checkout integration. An attacker can exploit this flaw to force an arbitrary paid subscription onto an existing member's account. This process allows the attacker to manipulate the member's profile, specifically the name field. Furthermore, the vulnerability enables the injection of malicious content, which is subsequently embedded into newsletters generated and distributed by the platform to the affected member. Depending on the email client's handling of the injected HTML, this can lead to successful HTML injection or Cross-Site Scripting (XSS) attacks. Defenders should prioritize patching, as this vulnerability allows for unauthorized modification of member data and potential delivery of malicious payloads via trusted communication channels.

## Impact

The vulnerability poses a significant risk to the integrity of member databases and the security of end-user communications. Successful exploitation allows attackers to associate paid subscriptions with arbitrary users and deliver malicious scripts directly to user email inboxes. This can lead to account takeover, theft of user credentials, or malicious redirects when victims interact with the injected content within the newsletter.

## Recommendation

* Upgrade all instances of Ghost to version 6.62.0 or later to remediate CVE-2026-103266.
* Audit recent member subscription history and newsletter delivery logs for anomalies associated with unauthorized Stripe checkout activity.
* Implement stricter input validation on member profile name fields to mitigate the potential impact of HTML and script injection during the patching window.
