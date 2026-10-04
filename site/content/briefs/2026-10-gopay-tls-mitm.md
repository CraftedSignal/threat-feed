---
title: TLS Verification Bypass in gopay Library
slug: 2026-10-gopay-tls-mitm
description: The gopay library versions prior to 1.5.119 contain a flaw in defaultClient() that disables TLS certificate verification, enabling man-in-the-middle attacks to intercept sensitive payment data.
date: "2026-10-04T18:54:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gopay:gopay:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - tls
  - mitm
  - library
vendors:
  - Gopay
products:
  - gopay (< 1.5.119)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: This vulnerability enables man-in-the-middle attackers to perform machine-in-the-middle attacks, allowing them to impersonate payment provider APIs.
    confidence_band: high
cves:
  - id: CVE-2026-105218
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105218
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade gopay to version 1.5.119 or later
      owner: Application Security
      due: 48h
      evidence: Source explicitly identifies version 1.5.119 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade gopay to version 1.5.119
      owner: IT Operations
      addresses: CVE-2026-105218
      evidence: NVD vulnerability notice
---

The gopay library versions before 1.5.119 exhibit a critical security flaw located in the defaultClient() function within the file pkg/xhttp/client.go. This function improperly disables TLS certificate verification, a security mechanism essential for ensuring encrypted communications remain private and authenticated. Consequently, this vulnerability allows a man-in-the-middle (MitM) attacker positioned on the network path between the application and the payment provider API to intercept, read, and modify traffic. 

An attacker exploiting this vulnerability can present fraudulent certificates to the application, effectively impersonating the payment provider. This enables the theft of sensitive merchant credentials, digital signatures, and transactional data. Furthermore, the attacker can manipulate the content of payment, refund, or order query responses, potentially leading to unauthorized financial operations or data integrity compromises. Defenders should prioritize updating to version 1.5.119 or later to enforce proper TLS validation.

## Impact

Successful exploitation of this vulnerability allows for unauthorized access to sensitive financial information, including merchant credentials and transaction data. An attacker can manipulate payment flows, potentially resulting in fraudulent transactions or incorrect refund processing. This flaw impacts any merchant application relying on the affected gopay library for payment integration, with the severity of potential damage proportional to the volume and criticality of transactions processed by the compromised system.

## Recommendation

* Upgrade the gopay dependency in all projects to version 1.5.119 or later to ensure TLS certificate verification is re-enabled.
* Audit application code for dependencies utilizing the affected defaultClient() function and ensure they are patched.
* Monitor network traffic for anomalous outbound connections from application servers to unknown or self-signed payment provider endpoints.
