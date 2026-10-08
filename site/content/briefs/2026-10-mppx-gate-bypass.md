---
title: Authentication Bypass in Insumer mppx Condition Gate Packages
slug: 2026-10-mppx-gate-bypass
description: The @insumermodel/mppx-condition-gate and @insumermodel/mppx-token-gate packages incorrectly trust a client-supplied wallet address, allowing attackers to bypass payment requirements by referencing any qualifying wallet address.
date: "2026-10-08T04:47:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:insumermodel:mppx-condition-gate:*:*:*:*:*:*:*:*
  - cpe:2.3:a:insumermodel:mppx-token-gate:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-104891
  - supply-chain
vendors:
  - Insumer
products:
  - '@insumermodel/mppx-condition-gate (<= 2.0.3)'
  - '@insumermodel/mppx-token-gate (<= 1.0.3)'
cves:
  - id: CVE-2026-104891
    cvss: 7.5
    epss: 0.00282
references:
  - https://github.com/advisories/GHSA-jg6q-3qfh-r9f8
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade or disable @insumermodel/mppx-condition-gate and mppx-token-gate
      owner: Application Security
      due: 24h
      evidence: 'Source states: Remove the condition gate from the payment method until a fixed version is installed.'
  mitigation_plan:
    - priority: immediate
      action: Remove the condition gate until fixed versions are deployed.
      owner: IT Operations
      addresses: CVE-2026-104891
      evidence: Source recommends removing the gate or ensuring the payment method binds the credential to the payer.
---

Research has identified a critical authentication bypass vulnerability, tracked as CVE-2026-104891, within the @insumermodel/mppx-condition-gate and @insumermodel/mppx-token-gate npm packages. These packages are designed to provide free-access pathways to paid services if a cryptocurrency wallet meets specific on-chain conditions. The vulnerability exists because the packages extract a payer address from a client-supplied DID (Decentralized Identifier) found in the `credential.source` field and query an external API to verify if that address satisfies the conditions. 

Crucially, the packages fail to verify that the requestor actually controls the wallet address they have supplied. Because qualifying wallet addresses are public chain state, an attacker can simply input a public address that meets the criteria to receive a successful access receipt. The packages perform this verification without calling the wrapped payment verifier, thereby bypassing the mandatory payment flow. An in-process cache, which defaults to a 300-second TTL keyed on the wallet address, then serves this unauthorized grant to subsequent requests without further validation. All published versions (up to 2.0.3 for mppx-condition-gate and 1.0.3 for mppx-token-gate) are affected.

## Impact

The vulnerability allows unauthorized users to access paid digital services without providing valid payment or proving control over a qualifying asset. By targeting the service-side implementation of the condition gate, attackers can effectively grant themselves free access to premium routes across any application utilizing these libraries. This represents a direct financial loss for service providers and potential mass abuse of protected digital assets.

## Recommendation

Prioritize the immediate removal of the condition gate from all payment methods until upgraded versions are deployed to the environment.

- Upgrade @insumermodel/mppx-condition-gate to a patched version beyond 2.0.3 and @insumermodel/mppx-token-gate to a version beyond 1.0.3 immediately upon availability.
- If immediate patching is not possible, disable the condition gate logic to force all requests through the standard paid payment path, ensuring that wallet control is verified via the wrapped payment verifier.
- Audit application-level logs to identify repeated requests that leverage high-value wallet addresses as `credential.source` inputs from disparate network origins, as this may indicate exploitation of the cache mechanism.
