---
title: Insecure Direct Object Reference in CRMEB gift-order API
slug: 2026-10-crmeb-idor
description: CRMEB versions 5.6.1 through 6.0.0 contain an IDOR vulnerability allowing authenticated attackers to enumerate and hijack order details via the gift-order API.
date: "2026-10-15T22:50:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:crmeb:crmeb:*:*:*:*:*:*:*:*
vendors:
  - CRMEB
products:
  - CRMEB (5.6.1 - 6.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can enumerate sequential order IDs in gift_detail to harvest buyer identities and the gift_key.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: call receive_gift to redirect paid goods to their address.
    confidence_band: high
cves:
  - id: CVE-2026-111359
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111359
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web access logs for sequential ID enumeration attempts against gift_detail endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-111359 description of IDOR via sequential enumeration
  mitigation_plan:
    - priority: immediate
      action: Patch CRMEB to a version post-6.0.0
      owner: IT Operations
      addresses: CVE-2026-111359
      evidence: NVD vulnerability report
---

CRMEB versions 5.6.1 through 6.0.0 are affected by an Insecure Direct Object Reference (IDOR) vulnerability within the gift-order API. This flaw stems from the application failing to properly validate user authorization when accessing order-related endpoints. An authenticated storefront user can exploit this to perform unauthorized actions on other customers' orders. By enumerating sequential order identifiers, an attacker can harvest sensitive buyer information and gift keys, eventually allowing them to intercept and redirect paid goods to an arbitrary address. This vulnerability poses a significant risk to the integrity of commerce transactions and customer data privacy within affected CRMEB deployments.

## Impact

Successful exploitation allows unauthorized access to sensitive buyer identities and the redirection of paid purchases. This results in direct financial loss to users and significant reputational damage to merchants using the affected CRMEB versions.

## Recommendation

* Apply the vendor-provided patch for CRMEB to address CVE-2026-111359.
* Monitor web application access logs for anomalous, high-frequency GET requests to gift_detail endpoints that exhibit sequential ID patterns.
* Implement strict authorization checks on all gift-order API endpoints to ensure users can only access objects associated with their own session or account UID.
