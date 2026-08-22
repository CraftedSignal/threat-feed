---
title: Stored XSS in J2Commerce via Guest Checkout Filter Bypass
slug: 2026-08-j2commerce-xss
description: J2Commerce versions 4.1.5 and earlier are vulnerable to stored XSS via guest checkout, allowing unauthenticated attackers to execute malicious JavaScript in the administrator's browser upon order review.
date: "2026-08-22T05:42:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - j2commerce
vendors:
  - J2Commerce
products:
  - J2Commerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker exploits a filter bypass in Joomla's Input::getArray() combined with PHP's variables_order=EGPCS to store unsanitized HTML.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: With admin-level JS execution, the attacker can trigger plugin installation endpoints to upload a PHP webshell.
    confidence_band: high
cves:
  - id: CVE-2026-74252
references:
  - https://sploitus.com/exploit?id=F87CD075-2D48-564B-991E-2FD88DED31C5
rules:
  - title: Detect CVE-2026-74252 Exploitation Attempt
    description: Detects potential exploitation attempts of J2Commerce XSS by identifying suspicious POST requests to the guest checkout endpoint with likely XSS payloads in cookies
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
    - action: Patch J2Commerce to 4.1.6 or later
      owner: IT Operations
      due: 24h
      evidence: Affected versions list includes 4.1.5 and earlier
  hunt_leads:
    - lead: Search for malicious scripts in order database billing fields
      technique_id: T1059.003
      data_needed:
        - Application database records
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Payload stored in j2store_orderinfos table
  mitigation_plan:
    - priority: immediate
      action: Upgrade J2Commerce
      owner: IT Operations
      addresses: CVE-2026-74252
      evidence: Security advisory states 4.1.6 as fixed
---

J2Commerce (com_j2store) versions 4.1.5 and earlier contain a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-74252) within the guest checkout billing address fields. The vulnerability is caused by a filter bypass in Joomla's `Input::getArray()` method, which can be exploited when PHP's `variables_order` configuration defaults to 'EGPCS' (Cookie overrides POST in `$_REQUEST`). 

An unauthenticated attacker can submit a malicious payload in cookie fields that are then stored unsanitized in the `j2store_orderinfos` database table. Because the J2Commerce administrator order management panel fails to encode these fields when rendering the orders list, the payload executes automatically in the administrator's browser as soon as the orders listing page is loaded. This allows for session hijacking, unauthorized creation of administrator accounts, or the installation of malicious plugins to achieve further system compromise. The vulnerability affects any hosting environment where cookies take precedence over POST data in `$_REQUEST`.

## Attack Chain

1. Attacker sends a GET request to the J2Commerce frontend to obtain a CSRF token.
2. Attacker adds an item to the cart using `option=com_j2store&view=carts&task=addItem`.
3. Attacker submits a POST request to `guest_validate` containing both a POST parameter `first_name=RAW` to trigger the filter bypass and a Cookie `first_name` containing the XSS payload.
4. Attacker completes the shipping validation step to set the necessary session data.
5. Attacker completes the payment selection step.
6. Attacker finalizes the order via `confirmPayment`, which causes the backend to store the unsanitized XSS payload in the database.
7. Administrator accesses the J2Commerce orders management interface.
8. The XSS payload executes automatically in the administrator's browser context, potentially leading to account takeover or webshell deployment.

## Impact

Successful exploitation results in full site compromise. An attacker can hijack administrative sessions, create new super-administrator accounts, or install malicious plugins to execute arbitrary PHP code on the server. Because the payload triggers automatically upon viewing the orders list, it requires no user interaction beyond the administrator's routine order management, and it persists until the malicious order record is removed.

## Recommendation

* Update J2Commerce (com_j2store) to version 4.1.6 or later to apply the necessary output encoding.
* Monitor web server access logs for anomalous POST requests to `com_j2store` checkout endpoints containing non-standard Cookie headers.
* Review J2Commerce orders database for suspicious values in the `billing_first_name`, `billing_last_name`, or address fields.
* Configure PHP `request_order` to exclude cookies (e.g., `request_order = "GP"`) if possible to prevent cookie-based override of input parameters, though this is a defense-in-depth measure.
