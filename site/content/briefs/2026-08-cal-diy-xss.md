---
title: Stored XSS in Cal.com Cal.diy via BookingPageTagManager
slug: 2026-08-cal-diy-xss
description: Cal.com Cal.diy versions 2.1.1 through 6.2.0 contain a stored XSS vulnerability allowing authenticated event owners to inject malicious JavaScript into public booking pages.
date: "2026-08-12T14:46:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Cal.com
products:
  - Cal.diy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The BookingPageTagManager component ... allows authenticated event owners to inject arbitrary JavaScript.
    confidence_band: high
cves:
  - id: CVE-2026-57858
    cvss: 8.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57858
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch Cal.diy to latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-57858 vulnerability disclosure
---

Cal.com Cal.diy versions 2.1.1 through 6.2.0 contain a stored cross-site scripting (XSS) vulnerability in the BookingPageTagManager component. The vulnerability arises due to a lack of sanitization for analytics tracking IDs provided by event owners. An attacker with authenticated access to an event account can supply a crafted tracking ID containing JavaScript payloads. When a user visits the public-facing booking page associated with that event, the malicious script executes within the visitor's browser session. 

This flaw poses a significant risk to organizations using Cal.diy for scheduling, as it allows for the theft of session cookies, the execution of unauthorized actions on behalf of the visitor, and potential wormable propagation. By chaining this XSS with cross-site request forgery (CSRF) vulnerabilities, an attacker could force persistent payload injection across multiple booking pages, escalating the impact of the compromise.

## Attack Chain

1. The attacker authenticates to their own Cal.diy account.
2. The attacker navigates to the event configuration or analytics settings menu.
3. The attacker locates the analytics tracking ID input field within the BookingPageTagManager settings.
4. The attacker submits a malicious tracking ID containing a JavaScript payload designed to break out of the script tag context.
5. The server fails to sanitize the input and saves the payload to the application database.
6. A legitimate victim visits the attacker-controlled public booking page.
7. The application renders the injected script in the victim's browser.
8. The script executes, resulting in session hijacking or subsequent unauthorized requests.

## Impact

Successful exploitation allows for the complete compromise of visitor browser sessions. Observed impacts include session hijacking, the ability to make authenticated requests as the visitor, and the potential for self-propagating payloads that affect other users of the booking platform. Given the public nature of these pages, any site visitor is a potential target.

## Recommendation

1. Immediately update Cal.diy to the latest version, which includes sanitization logic for the analytics tracking ID.
2. Audit event analytics configuration settings for any unexpected or suspicious script tags or obfuscated tracking identifiers.
3. Review logs for non-standard characters in analytics configuration API calls.
