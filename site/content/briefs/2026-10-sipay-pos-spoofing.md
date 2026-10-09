---
title: Cryptographic Signature Spoofing in Sipay PrestaShop Virtual POS Module
slug: 2026-10-sipay-pos-spoofing
description: CVE-2026-86405 describes a critical signature validation flaw in the Sipay PrestaShop Virtual POS Module allowing attackers to spoof transaction integrity checks and manipulate payment requests.
date: "2026-10-09T14:00:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:sipay:prestashop_virtual_pos_module:*:*:*:*:*:*:*:*
tags:
  - e-commerce
  - financial-services
  - vulnerability
  - signature-spoofing
vendors:
  - Sipay
products:
  - PrestaShop Virtual POS Module (26.8.1 <= version < 26.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558
    technique_name: Steal or Forge Authentication Certificates
    evidence: Improper verification of cryptographic signature vulnerability in Sipay Electronic Money and Payment Services Inc. PrestaShop Virtual POS Module allows Signature Spoofing by Improper Validation.
    confidence_band: high
cves:
  - id: CVE-2026-86405
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86405
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Sipay Virtual POS Module to version 26.9.1
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability for CVE-2026-86405.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Sipay Virtual POS Module to version 26.9.1
      owner: IT Operations
      addresses: CVE-2026-86405
      evidence: NVD vulnerability disclosure.
---

CVE-2026-86405 is a high-severity vulnerability within the Sipay Electronic Money and Payment Services Inc. Virtual POS module for the PrestaShop e-commerce platform. The vulnerability exists due to improper verification of cryptographic signatures during the payment processing workflow. Because the module fails to robustly validate the authenticity of signatures, an unauthenticated attacker can perform signature spoofing to bypass integrity checks. This flaw effectively allows unauthorized modification of payment parameters or the simulation of successful payment responses within the application environment. The vulnerability impacts versions of the module ranging from 26.8.1 to 26.9.0. Due to the high CVSS score of 9.8, this flaw represents a significant risk for merchants using the Sipay integration, as it facilitates direct financial manipulation and unauthorized transaction processing.

## Impact

Successful exploitation allows attackers to bypass payment integrity checks, leading to unauthorized transaction processing or the manipulation of payment request data. This poses an immediate financial risk to merchants relying on the Sipay Virtual POS module for payment processing, potentially leading to revenue loss and compromised e-commerce site integrity.

## Recommendation

* Upgrade the Sipay Virtual POS Module to version 26.9.1 or later to resolve the improper signature verification logic.
* Audit transaction logs for suspicious payment status transitions or inconsistencies between the internal PrestaShop order state and the expected payment provider callback data.
* Disable the Sipay Virtual POS integration if patching is not immediately feasible until the vendor-supplied fix can be applied.
