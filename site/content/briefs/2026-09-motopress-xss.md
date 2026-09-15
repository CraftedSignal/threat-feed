---
title: Stored Cross-Site Scripting in MotoPress Hotel Booking Plugin
slug: 2026-09-motopress-xss
description: The MotoPress Hotel Booking plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the Stripe webhook listener due to missing signature verification and improper output sanitization.
date: "2026-09-15T15:41:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:motopress:hotel_booking:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - plugin-vulnerability
vendors:
  - MotoPress
products:
  - Hotel Booking (<= 6.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-90650
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90650
rules:
  - title: Detect Potential Stripe Webhook Forgery Attempts
    description: Detects suspicious POST requests to the MotoPress Stripe webhook listener that may indicate an attempt to exploit CVE-2026-90650 by injecting payloads into webhook event fields
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade MotoPress Hotel Booking plugin to version 6.2.5 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability affects versions up to 6.2.4.
  mitigation_plan:
    - priority: immediate
      action: Configure a Stripe signing secret in the MotoPress plugin settings.
      owner: IT Operations
      addresses: CVE-2026-90650
      evidence: Source notes that the signature verification failure is due to an empty signing secret.
---

The MotoPress Hotel Booking plugin for WordPress, in versions up to and including 6.2.4, contains a vulnerability that allows unauthenticated attackers to execute Stored Cross-Site Scripting (XSS). The vulnerability exists within the premium Stripe gateway integration's webhook handler, located in `webhook-listener.php`. Because the plugin defaults to having no Stripe signing secret configured, the webhook handler fails to cryptographically verify incoming Stripe webhook events. An attacker can submit a forged webhook, such as a crafted 'refund.created' event, containing a malicious payload in the 'id' field of the event object. This payload is stored directly in the plugin's payment logs without sanitization. The vulnerability is triggered when an administrator subsequently accesses the payment logs through the WordPress dashboard, causing the stored script to execute within the administrator's session context. This vulnerability presents a significant risk to site administration, potentially leading to unauthorized actions or credential theft.

## Attack Chain

1. Attacker identifies a target WordPress site using the MotoPress Hotel Booking plugin with the premium Stripe integration enabled.
2. Attacker obtains a valid Stripe PaymentIntent ID associated with the target's legitimate payment records.
3. Attacker crafts a forged Stripe webhook request, setting the 'id' field of the event object to a malicious JavaScript payload.
4. Attacker sends the forged POST request to the plugin's webhook endpoint (typically accessible via public URL).
5. The `webhook-listener.php` script receives the POST request and, due to the default absence of a signing secret, fails to verify the signature.
6. The plugin extracts the malicious 'id' value from the request and writes it to the database as part of the payment log.
7. A site administrator logs into the WordPress dashboard and navigates to the payment history page.
8. The application displays the payment log, rendering the unsanitized malicious payload in the administrator's browser, triggering script execution.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator's browser session. This can result in unauthorized administrative actions, site configuration changes, theft of session tokens, or further compromise of the WordPress environment. The vulnerability impacts all users of the MotoPress Hotel Booking premium plugin running versions 6.2.4 and earlier.

## Recommendation

Prioritize the update of the MotoPress Hotel Booking plugin to version 6.2.5 or later to resolve the input validation and signature verification flaws associated with CVE-2026-90650. Ensure that a unique and complex Stripe signing secret is generated and configured in the plugin settings to enforce cryptographic signature verification for all incoming webhooks. Monitor web server logs for high volumes of POST requests to the plugin's webhook endpoint originating from non-Stripe IP addresses.
