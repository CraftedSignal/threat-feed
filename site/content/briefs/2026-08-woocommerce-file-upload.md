---
title: Unauthenticated Arbitrary File Upload in WooCommerce 1.5.0
slug: 2026-08-woocommerce-file-upload
description: WooCommerce 1.5.0 contains an unauthenticated arbitrary file upload vulnerability allowing remote attackers to upload malicious files, potentially resulting in remote code execution.
date: "2026-08-17T13:53:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - file-upload
  - remote-code-execution
vendors:
  - Automattic
products:
  - WooCommerce (1.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WooCommerce version 1.5.0 is vulnerable to an unauthenticated arbitrary file upload attack.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52642
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all WooCommerce installations and patch instances running version 1.5.0
      owner: IT Operations
      due: 24h
      evidence: WooCommerce 1.5.0 is confirmed vulnerable
  hunt_leads:
    - lead: Look for POST requests to unexpected directories or endpoints followed by GET requests to the same file path
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated arbitrary file upload vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch software
      owner: IT Operations
      addresses: WooCommerce 1.5.0
      evidence: Exploit-DB 52642
---

A vulnerability has been identified in WooCommerce version 1.5.0 that enables an unauthenticated attacker to upload arbitrary files to the target web server. This flaw, documented under Exploit-DB entry 52642, allows for the placement of malicious web shells or other scripts in accessible directories on the server. Because the vulnerability is exploitable without authentication, it poses a severe risk to any internet-facing instance of WooCommerce 1.5.0. Successful exploitation generally grants the attacker the ability to execute arbitrary code within the context of the web application process, leading to full site compromise, data exfiltration, or further lateral movement within the hosting environment. Defenders should prioritize updating instances to a secure version or ensuring appropriate file upload restrictions and monitoring are in place.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain remote code execution capabilities on the affected web server. This can result in complete loss of confidentiality, integrity, and availability for the WooCommerce store, unauthorized access to customer and transaction data, and the potential for the server to be used as a pivot point for broader network attacks.

## Recommendation

- Upgrade the WooCommerce installation to a patched version beyond 1.5.0 immediately to mitigate the risk of arbitrary file upload.
- Review web server access logs for anomalous POST requests targeting common upload endpoints with file extensions associated with server-side scripting (e.g., .php, .phtml, .php5).
- Implement strict file type validation and rename uploaded files to non-executable extensions at the web application level to prevent unauthorized script execution.
- Deploy web application firewall (WAF) rules to detect and block malicious file upload attempts targeting known vulnerable WooCommerce components.
