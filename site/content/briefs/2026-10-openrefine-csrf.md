---
title: CSRF Vulnerability in OpenRefine Leading to Remote Code Execution
slug: 2026-10-openrefine-csrf
description: OpenRefine versions up to 3.10.1 are vulnerable to a cross-site request forgery attack in the get-rows command that permits remote attackers to execute arbitrary Jython facet expressions and achieve system command execution.
date: "2026-10-10T15:55:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openrefine:openrefine:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - csrf
  - rce
vendors:
  - OpenRefine
products:
  - OpenRefine (<= 3.10.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can lure a user to a malicious page issuing a cross-origin GET with a crafted engine parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Allows remote attackers to execute Jython facet expressions.
    confidence_band: high
cves:
  - id: CVE-2026-108553
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108553
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all OpenRefine instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108553 vulnerability in OpenRefine 3.10.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenRefine beyond 3.10.1
      owner: IT Operations
      addresses: CVE-2026-108553
      evidence: Vulnerability in OpenRefine 3.10.1
---

OpenRefine versions through 3.10.1 contain a critical cross-site request forgery (CSRF) vulnerability residing within the get-rows command. This flaw allows a remote, unauthenticated attacker to execute arbitrary Jython facet expressions on the host server by inducing an authenticated OpenRefine user to visit a malicious, attacker-controlled webpage. Because OpenRefine facilitates data processing, the ability to inject and execute Jython code via the engine parameter during a cross-origin GET request can result in full remote command execution (RCE) with the privileges of the user running the OpenRefine application. This is particularly significant for local instances where the application is intended for trusted data cleaning but may be exposed to browser-based threats from the user's active session.

## Impact

Successful exploitation allows for remote command execution under the security context of the user running OpenRefine. This can lead to complete host compromise, unauthorized access to sensitive datasets processed by the application, and the potential for lateral movement within the network if the instance is deployed in a multi-user or server-based environment.

## Recommendation

Prioritized actions for security teams:
- Identify all instances of OpenRefine running in the environment using asset management tools or process monitoring.
- Upgrade all OpenRefine installations to a patched version beyond 3.10.1 as soon as an update is released by the vendor.
- Implement restrictive network access controls to ensure the OpenRefine management interface is not accessible from external, untrusted network segments.
- Disable Jython script execution features if they are not required for specific data transformation workflows.
