---
title: Integer Overflow in New-API Billing Settlement
slug: 2026-08-integer-overflow-billing
description: A critical integer overflow vulnerability in QuantumNous new-api allows authenticated users to inflate their account balance by injecting extreme quantity multipliers that result in negative settlement charges.
date: "2026-08-17T18:45:57Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - QuantumNous
exploited: true
vendors:
  - QuantumNous
products:
  - new-api (<= 1.0.0-rc.17)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A crafted extreme value makes conversions wrap past the int64 range into a large negative quota, crediting the user balance.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: With self-registration on by default and any of these enabled, an attacker can register to obtain seed balance for free.
    confidence_band: high
cves:
  - id: CVE-2026-71479
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-8r8v-xf7q-rcpr
  - https://github.com/QuantumNous/new-api/releases/tag/v1.0.0-rc.18
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade new-api to v1.0.0-rc.18 or higher.
      owner: IT Operations
      due: 24h
      evidence: Emergency fix released in v1.0.0-rc.18.
    - action: Audit user balances for anomalous spikes indicating balance inflation.
      owner: SOC
      due: 48h
      evidence: Exploitation confirmed to cause abnormally inflated balances.
  mitigation_plan:
    - priority: immediate
      action: Disable self-registration and new-user balance gifts until patching is complete.
      owner: IT Operations
      addresses: Preconditions for unauthenticated exploitation.
      evidence: Self-registration is the primary vector for seed balance creation.
---

The vulnerability CVE-2026-71479 affects the billing settlement logic in QuantumNous new-api versions 1.0.0-rc.17 and earlier. It stems from the application's failure to validate user-controlled quantity parameters, such as image counts or duration multipliers, before performing mathematical operations. By providing an extremely large numeric input that exceeds standard signed integer limits, an attacker triggers an overflow during type conversion (e.g., float64 to int64). This causes the settlement logic to calculate a massive negative cost for the transaction. Because the application treats this negative charge as a credit, the user's account balance is inflated instantly. This flaw is particularly dangerous for deployments with enabled self-registration or free sign-up bonuses, as it allows unauthenticated or low-privilege actors to gain and inflate seed balances, leading to the exhaustion of operator-prepaid upstream service funds.

## Attack Chain

1. Attacker performs account registration (if registration is enabled) or gains initial access to an account with a positive balance.
2. Attacker crafts a standard request to the billing-related API endpoint, including an extremely high integer value (e.g., 18446744073686646784) in the quantity parameter field.
3. The application's pre-consume check validates that the user has a sufficient balance for the request's nominal cost and permits the request to proceed.
4. The request payload is processed by the backend, bypassing input validation as the integer overflow check is missing at the ingress level.
5. The settlement module performs a mathematical operation (e.g., quota * quantity) using the uncontrolled, massive input.
6. The integer conversion wraps the calculation into a large negative value due to the absence of saturation logic or bounds checks.
7. The system registers the negative charge as a balance credit, updating the user's wallet with an inflated value.
8. Attacker repeats the process to drain upstream service funds or sell inflated quota balances.

## Impact

The vulnerability has been exploited in the wild, leading to massive unauthorized balance inflation and potential financial depletion of service providers. Attackers can leverage this to gain effectively unlimited API usage credits by mass-registering accounts that receive starter bonuses and then exploiting the overflow. Successful exploitation renders billing integrity void and risks the total loss of prepaid upstream funds.

## Recommendation

1. Upgrade to QuantumNous new-api version v1.0.0-rc.18 or later to implement required integer bounds checking and saturating math.
2. Implement request ingress validation to reject quantity parameters exceeding established architectural limits (400 Bad Request).
3. Monitor administrator audit logs for unusual quota saturation warnings related to CVE-2026-71479.
4. Audit historical user transaction logs for negative charge entries or abnormally high balance shifts consistent with the reported exploitation.
