---
title: Path Traversal in Mercado Pago Node.js SDK
slug: 2026-08-mercado-pago-path-traversal
description: The Mercado Pago Node.js SDK fails to sanitize user-supplied identifiers, allowing attackers to perform path traversal or query parameter injection to access unintended API endpoints within the merchant's token scope.
date: "2026-08-24T18:03:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Mercado Pago
products:
  - mercado-pago-sdk-nodejs
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that forwards an identifier influenced by an untrusted party into one of these methods without an ownership check therefore allows that party to reach other resources within the merchant's token scope.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: An attacker can supply identifiers... [to] reach other resources within the merchant's token scope.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76842
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory internal applications using mercado-pago-sdk-nodejs and audit input sanitization for payment API methods.
      owner: IT Operations
      due: 48h
      evidence: SDK methods build paths as template literals without encoding.
  mitigation_plan:
    - priority: immediate
      action: Enforce use of encodePathParam helper for all dynamic identifiers passed to SDK methods.
      owner: IT Operations
      addresses: CVE-2026-76842
      evidence: Repository contains helper encodePathParam in src/utils/path.ts that was not applied to affected modules.
---

The Mercado Pago Node.js SDK (mercado-pago-sdk-nodejs) contains a vulnerability (CVE-2026-76842) where identifiers provided by a caller are interpolated directly into API request path templates without proper percent-encoding. This affects several client modules, including payment, paymentRefund, advancedPayment, and disbursementRefund. Because the underlying logic uses template literals - such as RestClient.fetch(`/v1/payments/${id}`, ...) - attackers can supply identifiers containing path traversal sequences (e.g., "../") or query parameter delimiters (e.g., "?"). 

When an application integrates this SDK and processes user-supplied input as an identifier without strict validation, an attacker can manipulate the resulting URL to reach arbitrary endpoints under the merchant's account. Because the request carries the merchant's original access token, the attacker effectively gains the ability to make authenticated requests to unintended resources, potentially leading to unauthorized data exposure or service manipulation. A mitigation exists in the form of the encodePathParam utility function, which was omitted from the affected modules during previous refactoring.

## Impact

Successful exploitation allows an attacker to pivot from legitimate payment operations to other API endpoints within the same service scope. This could enable an attacker to exfiltrate sensitive payment information, list refund details, or cancel unauthorized transactions by manipulating the request path. Impact is high as it leverages the merchant's own authenticated session to bypass application-level authorization controls.

## Recommendation

- Update the mercado-pago-sdk-nodejs package to the latest version once a fix is released.
- Audit existing implementations of the affected clients (payment, paymentRefund, advancedPayment, disbursementRefund) to identify where user-supplied input is passed as identifiers.
- Implement strict input validation or use the existing encodePathParam helper located in src/utils/path.ts for all dynamic path parameters before passing them to the SDK.
- Review application-level logs for suspicious API request patterns featuring anomalous path structures or unexpected query parameters originating from the SDK's outbound connections.
