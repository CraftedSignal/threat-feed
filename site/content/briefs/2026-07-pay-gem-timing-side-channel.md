---
title: Non-Constant-Time HMAC Comparison in Pay Gem Paddle Billing Webhook Signature Verifier
slug: 2026-07-pay-gem-timing-side-channel
description: A timing side-channel vulnerability in the `Pay` gem's Paddle Billing webhook signature verification component (`Pay::Webhooks::PaddleBillingController#valid_signature?` <= v11.6.1) allows an unauthenticated attacker to recover the HMAC signing secret by observing response time variations in `String#==` comparisons, enabling the forgery of arbitrary webhook events and leading to business logic abuses such as unauthorized feature provisioning or fraudulent refunds.
date: "2026-07-03T12:39:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - timing-attack
  - vulnerability
  - webhooks
  - ruby-on-rails
  - server-side
  - logic-error
  - remote-code-execution
vendors:
  - Pay
products:
  - pay (rubygem) <= v11.6.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can deliver requests to the `/pay/webhooks/paddle_billing` mount point can probe the verifier
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A signature recovered through the oracle lets the attacker deliver forged Paddle Billing webhook events
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A signature recovered through the oracle lets the attacker deliver forged Paddle Billing webhook events
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mjgf-xj26-9qf9
---

The Ruby `Pay` gem, specifically versions equal to or older than 11.6.1, is vulnerable to a timing side-channel attack affecting its Paddle Billing webhook signature verification. The `Pay::Webhooks::PaddleBillingController#valid_signature?` method utilizes Ruby's non-constant-time `String#==` operator to compare the calculated HMAC with the attacker-supplied `Paddle-Signature` header. This allows an unauthenticated attacker to discern the correct HMAC character by character by observing subtle variations in response times. Successful exploitation grants the attacker the ability to forge arbitrary Paddle Billing webhook events, such as `subscription.created` or `transaction.completed`, which can lead to unauthorized provisioning of services, fraudulent refunds, or other business logic abuses within the victim application. The vulnerability is present in applications that mount `Pay::Engine` and enable `paddle_billing`, making the `POST /pay/webhooks/paddle_billing` endpoint publicly accessible to Paddle and, consequently, to attackers.

## Attack Chain

1.  **Initial Access:** An attacker identifies a Rails application utilizing the `Pay` gem (version <= 11.6.1) and exposing the `POST /pay/webhooks/paddle_billing` endpoint, which is publicly accessible for Paddle to deliver webhook events.
2.  **Information Gathering / Reconnaissance:** The attacker crafts a series of requests to the exposed webhook endpoint, supplying a valid timestamp (`ts=<now>`) and a systematically varying guessed HMAC signature (`h1=<guess>`) within the `Paddle-Signature` header.
3.  **Exploitation (Timing Side Channel):** The vulnerable application processes each request, internally calculating the true HMAC for the raw post data and comparing it to the attacker's `h1` guess using Ruby's `String#==`. Due to the non-constant-time nature of this comparison, the server's response time varies subtly based on how many leading characters of the `h1` guess match the true HMAC.
4.  **Credential Access (HMAC Key Recovery):** By sending a large number of requests and precisely measuring and analyzing the response times for each attempt, the attacker can use this timing oracle to accurately reconstruct the full 64-character hex-encoded SHA-256 HMAC, byte by byte, for a known payload.
5.  **Forging Webhooks:** Once the HMAC signing secret is effectively known (as the HMAC for any given payload can be computed), the attacker can generate valid `Paddle-Signature` headers for arbitrary Paddle Billing webhook payloads that they construct.
6.  **Impact (Business Logic Abuse):** The attacker then delivers these forged webhook events (e.g., `subscription.created`, `transaction.completed`, `invoice.paid`) to the `/pay/webhooks/paddle_billing` endpoint. The vulnerable application processes these forged events as legitimate, leading to unauthorized actions such as provisioning premium features for free, initiating fraudulent refunds, or triggering false customer notifications and database updates.

## Impact

This vulnerability (CWE-208: Observable Timing Discrepancy) allows an unauthenticated attacker to fully compromise the integrity of Paddle Billing webhook events. By recovering the HMAC signing secret through a timing side-channel, attackers can forge any webhook event, effectively tricking the application into believing Paddle Billing sent it. This can lead to significant financial losses through fraudulent transactions (e.g., free access to paid features, unauthorized refunds), customer confusion from incorrect notifications, or data integrity issues due to malicious updates to billing states. Since the webhook endpoint must be internet-reachable by design, all `Pay` gem installations integrating with Paddle Billing are exposed to this risk. No specific victim counts or sectors were identified in the source, but any organization using the affected `Pay` gem version is at risk.

## Recommendation

*   Immediately update the `pay` gem to a version greater than `11.6.1` to apply the fix that replaces the non-constant-time `String#==` comparison with `ActiveSupport::SecurityUtils.secure_compare`.
*   Review application logs for the `/pay/webhooks/paddle_billing` endpoint for unusually high request volumes from single IP addresses or abnormal response time distributions, which could indicate attempts at timing side-channel exploitation.
*   Review application-level audit logs for the `Pay` gem for any anomalous `subscription.created`, `transaction.completed`, or other financial event entries around the time of the vulnerability disclosure or patch deployment, as these could indicate forged events delivered by an attacker.
