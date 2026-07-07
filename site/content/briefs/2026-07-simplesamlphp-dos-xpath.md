---
title: SimpleSAMLphp Vulnerable to Denial-of-Service via Malicious XPath Transform
slug: 2026-07-simplesamlphp-dos-xpath
description: SimpleSAMLphp and its SAML2 library are vulnerable to CVE-2026-49289, allowing attackers to perform a Denial-of-Service attack by sending specially crafted SAML messages containing XPath transforms, leading to resource exhaustion and service unavailability.
date: "2026-07-03T11:25:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - saml
  - php
vendors:
  - SimpleSAMLphp
products:
  - composer/simplesamlphp/saml2 <= 4.20.2
  - composer/simplesamlphp/saml2-legacy <= 4.20.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Server Denial of Service
    evidence: An attacker is able to send specially crafted messages to any entity relying on SimpleSAMLphp (or directly on this SAML2-library) to be able to perform a Denial-of-Service attack.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5cjr-mxj5-wmrx
---

SimpleSAMLphp, a widely used open-source PHP application for SAML 2.0 service providers and identity providers, along with its underlying SAML2 library (composer/simplesamlphp/saml2 and composer/simplesamlphp/saml2-legacy), was found to be vulnerable to a Denial-of-Service (DoS) attack, tracked as CVE-2026-49289. The vulnerability, identified on or before July 2, 2026, arises from its handling of XPath transforms within SAML messages. Attackers can craft malicious SAML messages that, when processed by a vulnerable SimpleSAMLphp instance, cause resource exhaustion and lead to service interruption. This impacts any entity relying on these components and necessitates immediate updates to mitigate the risk of service disruption. A mitigation has been implemented in later versions (beyond 4.20.2) to restrict the number of transforms and disallow XPath transforms explicitly.

## Attack Chain

1.  An attacker identifies a target entity relying on SimpleSAMLphp for SAML processing.
2.  The attacker crafts a specially designed SAML message incorporating complex or excessive XPath transforms.
3.  The malicious SAML message is sent to the vulnerable SimpleSAMLphp instance, typically via an unauthenticated or authenticated SAML request/response endpoint.
4.  The SimpleSAMLphp application receives and begins parsing the incoming SAML message, including its XPath transforms.
5.  During the processing of the XPath transforms, the application consumes excessive system resources (CPU, memory).
6.  Due to resource exhaustion, the SimpleSAMLphp instance becomes unresponsive or crashes, leading to a Denial-of-Service for legitimate users.

## Impact

Successful exploitation of CVE-2026-49289 allows an attacker to render any entity relying on SimpleSAMLphp or the SAML2 library (versions <= 4.20.2) unavailable. This directly impacts the ability of legitimate users to authenticate or access services protected by SimpleSAMLphp, leading to significant operational disruption, reputational damage, and potential financial losses for affected organizations. The vulnerability affects critical authentication infrastructure, making it a high-priority concern for any organization utilizing SimpleSAMLphp.

## Recommendation

*   Patch CVE-2026-49289 by upgrading `composer/simplesamlphp/saml2` and `composer/simplesamlphp/saml2-legacy` to versions greater than 4.20.2 immediately.
*   Review the mitigation details provided in the GHSA-5cjr-mxj5-wmrx advisory for specific implementation guidance.
