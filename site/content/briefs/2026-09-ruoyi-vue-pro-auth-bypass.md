---
title: Improper Authorization Vulnerability in ruoyi-vue-pro
slug: 2026-09-ruoyi-vue-pro-auth-bypass
description: A remote authorization bypass in the ruoyi-vue-pro payment callback handler allows unauthorized manipulation of payment order states via the ID argument.
date: "2026-09-24T20:47:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yunaiv:ruoyi_vue_pro:*:*:*:*:*:*:*:*
vendors:
  - YunaiV
products:
  - ruoyi-vue-pro (<= 2026.08)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The attack can be initiated remotely.
    confidence_band: med
cves:
  - id: CVE-2026-97324
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97324
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to the demo payment callback endpoints
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-97324 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to validate the ID parameter for /admin/demo/pay/updateDemoOrderPaid
      owner: SOC
      addresses: CVE-2026-97324
      evidence: Vulnerability in updateDemoOrderPaid function
---

A security vulnerability (CVE-2026-97324) exists in the ruoyi-vue-pro platform, specifically within the Demo-order Payment Callback Handler. The flaw is located in the `updateDemoOrderPaid` function within the `PayDemoOrderController.java` file. An attacker can perform remote exploitation by manipulating the `ID` argument, leading to improper authorization. This vulnerability allows an unauthenticated or unauthorized user to interact with the payment callback logic, potentially forcing state changes in payment records. Given that functional exploit code is publicly available, organizations running versions of ruoyi-vue-pro up to 2026.08 are at risk. The vendor has not provided a patch as of the disclosure date, necessitating immediate compensatory controls at the network or application perimeter to prevent unauthorized access to these sensitive callback endpoints.

## Impact

Successful exploitation allows an unauthorized party to manipulate the state of demo payment orders. In a production environment, if this handler is repurposed or exposed, it could lead to logical failures in payment processing, financial data inconsistency, and potential unauthorized state modifications that may impact business operations.

## Recommendation

Prioritized actions for detection and mitigation:
- Implement strict IP allowlisting for the application’s administrative and callback endpoints to mitigate remote access.
- Deploy WAF rules to monitor for suspicious or unexpected `ID` parameter values targeting the `/admin/demo/pay` URI patterns.
- Review all custom modifications to `PayDemoOrderController.java` to ensure input validation and authorization checks are enforced before updating order records.
- Restrict internet exposure of the ruoyi-vue-pro admin interfaces if not required for business operations.
