---
title: Unauthenticated RCE in SPIP Crayons Plugin via CVE-2026-104070
slug: 2026-10-spip-crayons-auth-bypass
description: The Crayons plugin for SPIP before 3.5.0 contains a missing authorization flaw in crayons_store.php that allows unauthenticated attackers to modify arbitrary objects, leading to remote code execution.
date: "2026-10-06T18:57:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:spip:crayons_plugin:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - cve-2026-104070
vendors:
  - SPIP
products:
  - Crayons plugin (< 3.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Crayons plugin for SPIP before 3.5.0 contains a missing authorization vulnerability that allows unauthenticated attackers to modify arbitrary editable object fields
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can chain this flaw... to execute the uploaded skeleton, achieving arbitrary PHP code execution as the web-server user.
    confidence_band: high
cves:
  - id: CVE-2026-104070
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104070
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Crayons plugin to 3.5.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104070 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Crayons plugin to 3.5.0.
      owner: IT Operations
      addresses: CVE-2026-104070
      evidence: NVD vulnerability details
---

The Crayons plugin for SPIP, a content management system, contains a critical missing authorization vulnerability tracked as CVE-2026-104070. The vulnerability resides in 'crayons_store.php' and affects all versions prior to 3.5.0. By omitting the 'secu_' anti-forgery parameter, an unauthenticated attacker can force the authorization dispatcher to resolve an unconditionally-true handler. This bypass allows the attacker to modify arbitrary editable object fields within the SPIP installation. This vulnerability acts as a primitive for an escalation chain: attackers can use this access to write malicious '.html' skeleton files to the server, read site configuration files to extract the site secret, and ultimately sign a forged AJAX context to execute the uploaded malicious code, resulting in arbitrary PHP execution as the web-server user.

## Attack Chain

1. Attacker sends a crafted HTTP POST request to 'crayons_store.php' omitting the 'secu_' parameter.
2. The application's authorization dispatcher incorrectly resolves to an 'unconditionally-true' handler.
3. Attacker leverages the authorization bypass to perform unauthorized modification of site objects.
4. Attacker utilizes the modification capability to write a malicious '.html' skeleton file to a directory accessible by the web server.
5. Attacker targets sensitive configuration files to read and disclose the site secret key.
6. Attacker uses the disclosed site secret to sign a forged AJAX request.
7. Attacker executes the signed request to trigger the previously uploaded malicious skeleton file.
8. PHP code within the malicious skeleton is executed, granting the attacker arbitrary code execution privileges.

## Impact

Successful exploitation of CVE-2026-104070 grants an unauthenticated attacker full remote code execution capabilities on the host server. This allows for total system compromise, data exfiltration, and lateral movement within the target network. Given the nature of SPIP as a CMS, this vulnerability poses a high risk to all public-facing websites utilizing the Crayons plugin in versions prior to 3.5.0.

## Recommendation

1. Upgrade the Crayons plugin for SPIP to version 3.5.0 or later immediately.
2. Audit web server logs for suspicious POST requests to 'crayons_store.php' that lack the 'secu_' parameter or exhibit unconventional 'crayons' action patterns.
3. Monitor for unauthorized file creation events in directories where SPIP stores skeleton files (typically '/squelettes/').
