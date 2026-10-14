---
title: 'CVE-2026-104800: Unauthenticated Remote Code Execution in AGE-GATE WordPress Plugin'
slug: 2026-10-age-gate-rce
description: An unauthenticated remote code execution vulnerability in AGE-GATE WordPress plugin version 1.0 and earlier allows attackers to inject PHP code via unsanitized POST parameters.
date: "2026-10-14T04:35:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:age-gate_project:age-gate:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - AGE-GATE (<= 1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is possible because admin.php does not load WordPress and carries no ABSPATH guard, making it a fully unauthenticated entry point.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-104800
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104800
rules:
  - title: Detect CVE-2026-104800 Exploitation - Malicious POST to AGE-GATE Plugin
    description: Detects exploitation attempts against the AGE-GATE plugin where arbitrary PHP code is injected via POST parameters to the standalone admin.php endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all WordPress sites to identify AGE-GATE plugin version.
      owner: SOC
      due: 24h
      evidence: AGE-GATE plugin is vulnerable to RCE.
    - action: Deploy Sigma detection rule to monitor for exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Plugin lacks authentication and nonce verification.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove the AGE-GATE plugin until a patch is available.
      owner: IT Operations
      addresses: CVE-2026-104800
      evidence: All versions up to and including 1.0 are vulnerable.
---

The AGE-GATE plugin for WordPress (versions 1.0 and earlier) contains a critical Remote Code Execution (RCE) vulnerability identified as CVE-2026-104800. The flaw resides within a standalone admin.php endpoint that lacks standard WordPress security controls, including authentication, capability checks, and nonce verification. Furthermore, the endpoint does not implement the necessary ABSPATH guards, allowing direct execution of the file without loading the WordPress framework. 

Attackers can exploit this by submitting specially crafted POST requests containing malicious PHP code within the 'width' or 'height' parameters. This input is processed without sanitization and written directly into a PHP file that is subsequently executed by the server. This vulnerability provides unauthenticated actors with the ability to execute arbitrary code with the permissions of the web server user, leading to potential full system compromise, data exfiltration, or backdooring of the WordPress environment.

## Impact

Successful exploitation allows unauthenticated remote code execution, granting attackers the ability to run arbitrary system commands, modify site content, or gain unauthorized access to the underlying server. Given the nature of WordPress deployments, this affects a broad range of websites using the AGE-GATE plugin, potentially leading to widespread site defacement or the deployment of persistent web shells for further malicious activity.

## Recommendation

* Identify and audit all WordPress installations utilizing the AGE-GATE plugin to determine if version 1.0 or earlier is currently deployed.
* Disable or remove the AGE-GATE plugin immediately until a patched version is available from the vendor.
* Monitor web server access logs for anomalous POST requests directed at the `/wp-content/plugins/age-gate/admin.php` endpoint.
* Deploy WAF rules to inspect POST request bodies for PHP syntax or unexpected special characters in the 'width' and 'height' parameters.
