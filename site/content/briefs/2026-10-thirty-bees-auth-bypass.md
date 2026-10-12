---
title: Authentication Bypass in Thirty bees PasswordController
slug: 2026-10-thirty-bees-auth-bypass
description: Thirty bees versions up to 1.7.0 are vulnerable to an authentication bypass in PasswordController::resolveCustomer() that enables account takeover via manipulated guest checkout processes.
date: "2026-10-12T18:33:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thirtybees:thirty_bees:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - e-commerce
  - account-takeover
vendors:
  - Thirty bees
products:
  - Thirty bees (<= 1.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Thirty bees through 1.7.0 contains an authentication bypass vulnerability in PasswordController::resolveCustomer() that allows unauthenticated attackers to reset registered customers' passwords using guest account tokens.
    confidence_band: high
cves:
  - id: CVE-2026-109394
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109394
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Review guest checkout configuration in Thirty bees deployment
      owner: IT Operations
      due: 24h
      evidence: Exploit requires guest checkout to be enabled.
  mitigation_plan:
    - priority: immediate
      action: Disable guest checkout functionality until a secure patch is installed
      owner: IT Operations
      addresses: CVE-2026-109394
      evidence: Vulnerability relies on guest order tokens to initiate password reset.
---

Thirty bees through version 1.7.0 contains an authentication bypass vulnerability located in the PasswordController::resolveCustomer() method. This vulnerability stems from improper validation of guest account tokens, which allows an unauthenticated remote attacker to reset the passwords of registered customers. The attack requires the platform to have the guest checkout functionality enabled. By placing a guest order using a targeted victim's email address, an attacker can obtain a guest secure key. This key is then abused to manipulate the password reset flow, effectively allowing the attacker to take over the victim's account. This flaw poses a significant risk to user data integrity and account security for e-commerce sites running affected versions of the Thirty bees platform.

## Impact

Successful exploitation results in full account takeover of registered customers on affected e-commerce platforms. Attackers can gain unauthorized access to customer account information, order history, and potentially payment-related data linked to the profile. This vulnerability impacts any organization running Thirty bees version 1.7.0 or earlier with guest checkout enabled.

## Recommendation

Prioritized actions for administrators of Thirty bees environments:

* Immediately audit current configurations to determine if guest checkout is enabled, as this is a prerequisite for exploitation.
* Monitor application logs for anomalous password reset requests or unexpected patterns associated with guest checkout flows.
* Verify if an update is available from the vendor that patches the PasswordController::resolveCustomer() method and apply it immediately to address CVE-2026-109394.
* If no patch is available, consider disabling the guest checkout functionality until a secure version is deployed.
