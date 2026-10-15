---
title: NivoCart Unauthorized Invoice Disclosure Vulnerability
slug: 2026-10-nivocart-auth-bypass
description: NivoCart through 2.5.1 contains a missing authorization vulnerability in the account/order module that allows unauthenticated attackers to exfiltrate guest order invoices by iterating order identifiers.
date: "2026-10-15T22:49:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nivocart:nivocart:*:*:*:*:*:*:*:*
vendors:
  - NivoCart
products:
  - NivoCart (<= 2.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can iterate the order_id parameter... to disclose guest names, addresses, telephone numbers, emails, purchased items, and totals.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111277
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review web server logs for anomalous patterns of requests to order download endpoints
      owner: SOC
      due: 24h
      evidence: Unauthenticated attackers iterate the order_id parameter
  mitigation_plan:
    - priority: immediate
      action: Monitor for official security patch and upgrade NivoCart beyond version 2.5.1
      owner: IT Operations
      addresses: CVE-2026-111277
      evidence: NivoCart through 2.5.1 contains a missing authorization vulnerability
---

NivoCart versions up to and including 2.5.1 contain a significant authorization vulnerability within the `download()` action of the `account/order` module. This flaw stems from a failure to verify the requester's identity or permissions before processing invoice retrieval requests. An unauthenticated attacker can exploit this by sending crafted HTTP requests to the application, specifically targeting the `order_id` parameter. Because the application fails to restrict access to records where the `customer_id` is set to 0 (the identifier used for guest checkouts), an attacker can systematically enumerate these IDs to scrape private customer data. This vulnerability poses a high risk to data privacy, as it permits unauthorized access to names, physical addresses, telephone numbers, email addresses, and granular purchase history.

## Impact

Successful exploitation leads to mass exfiltration of customer PII and sensitive purchase information. The ability to enumerate guest orders allows an attacker to build comprehensive lists of customer profiles and transaction records. This breach of confidentiality impacts individual user privacy and may result in regulatory non-compliance for organizations hosting vulnerable NivoCart instances.

## Recommendation

1. Patch immediately by upgrading NivoCart to a version beyond 2.5.1 as soon as a security update is released by the vendor.
2. Implement an application-level web access control list or WAF rule to block suspicious patterns of sequential `order_id` requests originating from a single IP address.
3. Audit web server logs for high-frequency requests to `/account/order/download` or equivalent endpoints featuring incrementing `order_id` integer values.
