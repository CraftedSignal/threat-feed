---
title: IDOR Vulnerability in Jeepay Payment Configuration
slug: 2026-10-jeepay-idor
description: An insecure direct object reference vulnerability in Jeepay versions 3.2.9 and earlier allows authenticated merchant users to overwrite arbitrary payment channel configurations, enabling payment redirection or service disruption.
date: "2026-10-16T18:46:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:jeepay:jeepay:*:*:*:*:*:*:*:*
tags:
  - idor
  - payment-security
  - financial-fraud
vendors:
  - Jeepay
products:
  - Jeepay (<= 3.2.9)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can replace signing keys, certificates, and fee rates to break or redirect the victim merchant's payment processing.
    confidence_band: high
cves:
  - id: CVE-2026-111607
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111607
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Jeepay to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111607 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jeepay version
      owner: IT Operations
      addresses: CVE-2026-111607
      evidence: NVD vulnerability entry
---

Jeepay, an open-source payment system, contains an insecure direct object reference (IDOR) vulnerability identified as CVE-2026-111607. The vulnerability exists in the MchPayInterfaceConfigController.saveOrUpdate method, which fails to properly validate the ownership of the payment channel configuration being updated. Authenticated merchant users possessing the default ENT_MCH_PAY_CONFIG_ADD permission can exploit this flaw by manipulating the infoId parameter in their requests. By substituting the infoId with that of a victim merchant, an attacker can overwrite critical payment settings, including signing keys, certificates, and fee rates. This allows for the redirection of payment traffic, potential theft of transaction funds, or complete denial of service for the targeted merchant. This vulnerability impacts all Jeepay deployments version 3.2.9 and earlier.

## Impact

Successful exploitation results in unauthorized modification of payment processing infrastructure. Victims face significant financial risk, as attackers can intercept transaction signing parameters, redirect payments to unauthorized channels, or disrupt payment operations. This vulnerability poses a severe risk to multi-tenant payment platforms where merchant isolation is critical for financial integrity.

## Recommendation

* Apply the vendor-provided patch or upgrade to a version of Jeepay beyond 3.2.9 immediately to resolve CVE-2026-111607.
* Audit access logs for the MchPayInterfaceConfigController.saveOrUpdate endpoint to identify requests where the infoId parameter does not align with the authenticated session's merchant ID.
* Review merchant permission assignments to identify users holding the ENT_MCH_PAY_CONFIG_ADD privilege who should not have access to manage payment configurations.
