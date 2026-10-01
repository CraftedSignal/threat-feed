---
title: Unauthenticated Stripe Checkout Manipulation in Ghost
slug: 2026-10-ghost-stripe-vuln
description: A vulnerability in Ghost versions 5.2.0 through 6.61.9 allows unauthenticated remote attackers to manipulate Stripe Checkout flows to modify member records and inject malicious content into newsletters.
date: "2026-10-01T12:42:24Z"
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
vendors:
  - Ghost
products:
  - Ghost (5.2.0 - 6.61.9)
cves:
  - id: CVE-2026-103266
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103266
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
---

Ghost versions 5.2.0 through 6.61.9 are susceptible to an unauthenticated vulnerability within the Stripe Checkout integration. An attacker can exploit this flaw to force an arbitrary paid subscription onto an existing member's account. This process allows the attacker to manipulate the member's profile, specifically the name field. Furthermore, the vulnerability enables the injection of malicious content, which is subsequently embedded into newsletters generated and distributed by the platform to the affected member. Depending on the email client's handling of the injected HTML, this can lead to successful HTML injection or Cross-Site Scripting (XSS) attacks. Defenders should prioritize patching, as this vulnerability allows for unauthorized modification of member data and potential delivery of malicious payloads via trusted communication channels.

## Impact

The vulnerability poses a significant risk to the integrity of member databases and the security of end-user communications. Successful exploitation allows attackers to associate paid subscriptions with arbitrary users and deliver malicious scripts directly to user email inboxes. This can lead to account takeover, theft of user credentials, or malicious redirects when victims interact with the injected content within the newsletter.

## Recommendation

* Upgrade all instances of Ghost to version 6.62.0 or later to remediate CVE-2026-103266.
* Audit recent member subscription history and newsletter delivery logs for anomalies associated with unauthorized Stripe checkout activity.
* Implement stricter input validation on member profile name fields to mitigate the potential impact of HTML and script injection during the patching window.
