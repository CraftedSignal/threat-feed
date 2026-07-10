---
title: MPP Multiple Payment Bypass and Griefing Vulnerabilities
slug: 2024-01-mpp-payment-bypass
description: Multiple vulnerabilities were discovered in mpp versions prior to 0.8.0 that allowed for payment bypass and griefing, including performing free charge and session requests, replaying existing charge requests, piggybacking and griefing existing session channels, manipulating fee payers, and replaying stripe charge requests.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - payment-bypass
  - griefing
  - rust
products:
  - mpp
references:
  - https://github.com/advisories/GHSA-fxc9-7j2w-vx54
rules:
  - title: Detect suspicious tempo/charge requests
    description: Detects suspicious tempo/charge requests indicative of payment bypass vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect suspicious tempo/session requests
    description: Detects suspicious tempo/session requests indicative of payment bypass vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `mpp` crate, a Rust library, contains multiple critical vulnerabilities affecting versions prior to 0.8.0. These vulnerabilities allow for a range of malicious activities, including bypassing payment requirements, manipulating payment fees, and griefing existing sessions. Specifically, attackers can perform free `tempo/charge` and `tempo/session` requests, replay existing `tempo/charge` requests, piggyback off existing `tempo/session` channels, grief existing `tempo/session` channels, manipulate the fee payer, and replay existing `stripe/charge` requests. Given the severity of these issues, organizations utilizing `mpp` in their payment processing systems are at significant risk. Upgrade to version 0.8.0 is the only remediation.

## Attack Chain

1. An attacker identifies a vulnerable `mpp` instance running a version prior to 0.8.0.
2. The attacker crafts a `tempo/charge` request, exploiting the vulnerability to bypass payment verification.
3. The attacker sends the crafted request to the `mpp` instance, resulting in a free charge.
4. Alternatively, the attacker replays a previously valid `tempo/charge` request, bypassing payment verification.
5. The attacker exploits the `tempo/session` vulnerability to gain unauthorized access to an existing session.
6. The attacker piggybacks off the existing `tempo/session` channel for malicious purposes.
7. The attacker can also grief the `tempo/session` channel, disrupting legitimate user activity.
8. The attacker may also manipulate the fee payer information within tempo or stripe charge/session handlers to force another party to pay for their requests.

## Impact

Successful exploitation of these vulnerabilities can lead to significant financial losses due to payment bypass. Attackers can perform unauthorized transactions, manipulate fees, and disrupt legitimate services. The absence of available workarounds prior to patching amplifies the risk. Organizations utilizing the vulnerable versions of `mpp` are exposed to potential fraud and service disruption. The severity is considered critical due to the direct impact on payment processing integrity and potential for widespread abuse.

## Recommendation

*   Immediately upgrade `mpp` to version 0.8.0 to remediate the vulnerabilities.
*   Implement network monitoring to detect and block replay attacks targeting `tempo/charge` or `stripe/charge` requests.
*   Review logs for unexpected free `tempo/charge` or `tempo/session` requests after patching.
*   Monitor payment gateways for unusual activity, such as manipulated fee payers.
