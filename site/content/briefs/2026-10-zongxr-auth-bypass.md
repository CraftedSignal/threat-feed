---
title: Authentication Bypass in ZongXR Supermarket via OrderController
slug: 2026-10-zongxr-auth-bypass
description: ZongXR Supermarket version 1.0.0.0 contains an authentication bypass vulnerability in the OrderController.addOrder function, enabling remote unauthorized order manipulation via the userId parameter.
date: "2026-10-01T06:38:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zongxr:supermarket:1.0.0.0:*:*:*:*:*:*:*
vendors:
  - ZongXR
products:
  - Supermarket (1.0.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-103536
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103536
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the /save endpoint of the ZongXR Supermarket application
      owner: IT Operations
      due: 24h
      evidence: The attack can be executed remotely.
  mitigation_plan:
    - priority: immediate
      action: Monitor server logs for unauthorized userId parameter values targeting the OrderController.addOrder endpoint
      owner: SOC
      addresses: CVE-2026-103536
      evidence: The exploit is publicly available and might be used.
---

A critical authentication vulnerability exists in ZongXR Supermarket version 1.0.0.0, specifically within the OrderController.addOrder function located in the file order/src/main/java/com/supermarket/order/controller/OrderController.java. The vulnerability manifests in the 'save' endpoint, where improper validation of the 'userId' argument allows remote attackers to bypass authentication mechanisms. Because the application fails to verify the identity of the user submitting the order, an attacker can manipulate orders on behalf of other users. Proof-of-concept exploit code is publicly available, increasing the risk of exploitation by unauthorized actors. As of the reporting date, the maintainers of the ZongXR Supermarket project have not responded to the vulnerability report, and no official patch is available. Defenders should restrict access to the affected web application endpoints.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to perform order manipulation, potentially leading to financial fraud, unauthorized data access, and compromise of legitimate customer accounts. The flaw is remotely exploitable and currently has public exploit availability, posing a high risk to any instance of ZongXR Supermarket 1.0.0.0 exposed to the internet.

## Recommendation

- Monitor web server access logs for anomalous POST requests to the /save endpoint containing non-standard or unexpected 'userId' values.
- Implement strict network-level access controls to restrict exposure of the ZongXR Supermarket application to known, trusted management IPs until a patch is released.
- Deploy Web Application Firewall (WAF) rules to inspect the 'userId' parameter in POST requests to ensure only authorized numeric or session-validated identifiers are accepted.
- Prioritize the isolation of the affected service, as the maintainers have not yet addressed the reported issue.
