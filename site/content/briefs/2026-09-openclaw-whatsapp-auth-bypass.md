---
title: Authorization Bypass in @openclaw/whatsapp npm package
slug: 2026-09-openclaw-whatsapp-auth-bypass
description: The @openclaw/whatsapp npm package prior to version 2026.8.1 contains an authorization bypass vulnerability (CVE-2026-100532) allowing non-owner users to trigger the WhatsApp login tool, resulting in service disruption via account disconnection.
date: "2026-09-26T06:57:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw_whatsapp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - npm
  - supply-chain
vendors:
  - openclaw
products:
  - '@openclaw/whatsapp (< 2026.8.1)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An admitted non-owner sender able to steer the tool can request a forced login and receive a new QR code for a configured account, disconnecting the Gateway's WhatsApp account and causing loss of availability.
    confidence_band: high
cves:
  - id: CVE-2026-100532
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100532
action_plan:
  priority: elevated
  owners:
    - Application Security
    - DevOps
  immediate_actions:
    - action: Upgrade @openclaw/whatsapp to 2026.8.1
      owner: DevOps
      due: 48h
      evidence: Fixed in 2026.8.1.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @openclaw/whatsapp to 2026.8.1
      owner: IT Operations
      addresses: CVE-2026-100532
      evidence: Fixed in 2026.8.1.
---

The @openclaw/whatsapp npm package, used for integrating WhatsApp functionality, contains a critical authorization flaw (CVE-2026-100532) in versions prior to 2026.8.1. The vulnerability stems from a failure to enforce the 'owner-only' security boundary on the generic channel-tool path used for the WhatsApp login process. 

By design, the login tool should only be accessible to the configured owner of the service. However, because the tool fails to preserve or validate the sender's owner status during the interaction, any non-owner user capable of steering the tool can invoke the login functionality. This action forces the service to generate a new QR code for a configured account. This process effectively disconnects the currently active WhatsApp account from the Gateway, leading to a denial-of-service condition. While the primary impact is service disruption, an attacker with physical access to the device can perform a subsequent QR code scan to relink the gateway to an account of their choosing, leading to unauthorized account control.

## Impact

Successful exploitation leads to immediate denial-of-service as the active WhatsApp account is disconnected from the Gateway. In scenarios where an attacker can scan the newly generated QR code, they can hijack the gateway's WhatsApp integration. This vulnerability affects all environments deploying @openclaw/whatsapp versions earlier than 2026.8.1.

## Recommendation

* Immediately upgrade the @openclaw/whatsapp dependency to version 2026.8.1 or later.
* Audit logs for unauthorized access attempts to the login tool path or unexpected QR code generation events triggered by non-administrative service accounts.
* Implement stricter access control logic at the application layer if upgrading is delayed, ensuring only authorized user IDs are permitted to interact with the channel-tool path.
