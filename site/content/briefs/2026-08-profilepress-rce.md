---
title: Unauthenticated Remote Code Execution in ProfilePress WordPress Plugin
slug: 2026-08-profilepress-rce
description: The ProfilePress WordPress plugin contains an unauthenticated RCE vulnerability (CVE-2026-66047) caused by a predictable 32-bit connect token in the AJAX handler, allowing remote attackers to install malicious plugins.
date: "2026-08-31T15:58:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:profilepress:profilepress:*:*:*:*:*:wordpress:*:*
vendors:
  - ProfilePress
products:
  - ProfilePress (< 4.17.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ProfilePress WordPress plugin contains an unauthenticated remote code execution vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker can trigger silent plugin installation and activation, achieving PHP code execution as the web-server user.
    confidence_band: high
cves:
  - id: CVE-2026-66047
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66047
rules:
  - title: Detect CVE-2026-66047 Exploitation - Brute-force Attempt on ppress_connect_process
    description: Detects suspicious high-frequency POST requests to the ProfilePress AJAX handler, which may indicate an attacker attempting to brute-force the 32-bit connect token.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update ProfilePress plugin to 4.17.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin version required to patch CVE-2026-66047.
  mitigation_plan:
    - priority: immediate
      action: Patch ProfilePress to 4.17.2.
      owner: IT Operations
      addresses: CVE-2026-66047
      evidence: Source advisory specifies version 4.17.2 for fix.
---

The ProfilePress WordPress plugin (formerly wp-user-avatar) versions prior to 4.17.2 are vulnerable to an unauthenticated remote code execution exploit identified as CVE-2026-66047. The vulnerability exists within the ppress_connect_process AJAX handler, which utilizes a weak 32-bit connect token for authentication. Attackers can brute-force this token to bypass authorization and interface with the handler. Once the token is discovered, an attacker can supply a malicious URL via the file request parameter, instructing the server to download and activate a ZIP file containing a WordPress plugin of the attacker's choosing. This process results in arbitrary PHP code execution within the context of the web-server user. This vulnerability is critical for WordPress administrators as it provides a trivial path to full site compromise without requiring any prior authentication.

## Impact

Successful exploitation allows unauthenticated attackers to achieve arbitrary code execution on the underlying server. This can lead to full site takeover, unauthorized access to sensitive database information, exfiltration of user data, and potential lateral movement within the hosting environment. All WordPress sites running versions of ProfilePress prior to 4.17.2 are at risk.

## Recommendation

* Update the ProfilePress WordPress plugin to version 4.17.2 or later immediately.
* Monitor webserver access logs for high-frequency POST requests to the 'admin-ajax.php' endpoint, specifically targeting the 'ppress_connect_process' action, which may indicate a brute-force attempt against the 32-bit connect token.
* Review installed WordPress plugins for unauthorized additions or suspicious activity originating from the plugin directory.
