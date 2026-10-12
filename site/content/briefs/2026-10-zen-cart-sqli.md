---
title: SQL Injection in Zen Cart PayPal IPN Handler
slug: 2026-10-zen-cart-sqli
description: A remote SQL injection vulnerability in the Zen Cart PayPal IPN Handler component allows unauthenticated attackers to execute arbitrary SQL commands via the txn_id parameter.
date: "2026-10-12T11:42:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zen-cart:zen_cart:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sql-injection
  - e-commerce
vendors:
  - Zen Cart
products:
  - Zen Cart (<= 2.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely via manipulation of the argument txn_id.
    confidence_band: high
cves:
  - id: CVE-2026-108826
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108826
rules:
  - title: Detect CVE-2026-108826 Exploitation - SQL Injection in PayPal IPN Handler
    description: Detects potential SQL injection attempts against the Zen Cart PayPal IPN Handler by looking for suspicious SQL syntax in the txn_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Zen Cart to the version containing the fix for commit 557154f4fa025f51553094f47b06aa024220c48f
      owner: IT Operations
      due: 24h
      evidence: Source document requires patch to address the issue
  mitigation_plan:
    - priority: immediate
      action: Apply the official patch from Zen Cart
      owner: IT Operations
      addresses: CVE-2026-108826
      evidence: Source recommends installing the patch
---

A SQL injection vulnerability (CVE-2026-108826) has been identified in Zen Cart versions up to 2.2.2. The flaw resides in the 'zen_db_perform' function within the 'includes/modules/payment/paypaldp.php' file, which is part of the PayPal IPN Handler component. An unauthenticated remote attacker can exploit this by manipulating the 'txn_id' argument supplied to the handler. Successful exploitation allows for the execution of arbitrary SQL queries, which could lead to data exfiltration, unauthorized modification of database contents, or further application compromise. The vulnerability is confirmed to have public exploit code available, and a patch is available via commit 557154f4fa025f51553094f47b06aa024220c48f.

## Impact

The vulnerability poses a high risk to merchants utilizing the affected versions of Zen Cart. If successfully exploited, the database containing customer information, transaction history, and potentially administrative credentials could be fully compromised. This impacts the confidentiality and integrity of e-commerce data for organizations running this specific version of the payment module.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Patch the Zen Cart installation by applying the fix provided in commit 557154f4fa025f51553094f47b06aa024220c48f immediately.
- Review web server access logs for anomalous POST requests directed at the 'includes/modules/payment/paypaldp.php' file containing suspicious characters in the 'txn_id' parameter, such as single quotes, semicolons, or SQL keywords.
- Audit database query logs for unauthorized or unexpected queries originating from the web application user, particularly those that correlate with the access patterns observed for the vulnerable script.
