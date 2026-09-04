---
title: Remote Code Execution in Grav via Twig sort filter
slug: 2026-09-grav-rce
description: Grav versions 2.0.17 and earlier contain a remote code execution vulnerability in the Twig sort filter that allows authenticated users with page-write permissions to execute arbitrary PHP code.
date: "2026-09-04T13:25:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - php
vendors:
  - GetGrav
products:
  - Grav (<= 2.0.17)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An authenticated user with only page-write rights can supply a crafted payload that invokes spl_autoload through the sort filter, resulting in arbitrary PHP execution.
    confidence_band: high
cves:
  - id: CVE-2026-85604
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85604
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav instances to 2.0.19 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85604 vendor advisory remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Grav 2.0.19
      owner: IT Operations
      addresses: CVE-2026-85604
      evidence: NVD vulnerability disclosure
---

Grav versions 2.0.17 and earlier are vulnerable to remote code execution (CVE-2026-85604) due to a security flaw in the Twig 'sort' filter. The vulnerability originates in the 'sortFunc' wrapper within 'GravExtension.php', which incorrectly sets the Twig 'isSandboxed' argument to 'false'. While other filters like 'map', 'filter', and 'reduce' correctly maintain sandbox restrictions, the 'sort' filter fails to prevent the use of arbitrary PHP functions. Specifically, the internal denylist fails to block 'spl_autoload', which can be leveraged to perform unauthorized PHP file inclusions. An attacker with minimal 'admin.pages' or 'api.pages.write' privileges can inject a crafted payload into form frontmatter or other page-rendering components, leading to arbitrary code execution under the context of the web server process. Defenders should upgrade to Grav 2.0.19 or later to remediate this vulnerability.

## Impact

Successful exploitation of CVE-2026-85604 results in full remote code execution on the server hosting the Grav instance. This allows attackers to bypass application-level access controls, potentially leading to total system compromise, data theft, and persistence. The vulnerability is restricted to authenticated users with page-write capabilities, limiting the attack surface to malicious insiders or compromised administrative accounts.

## Recommendation

* Upgrade all instances of Grav to version 2.0.19 or later immediately.
* Audit logs for administrative accounts (admin.pages or api.pages.write permissions) for suspicious activity or anomalous page updates.
* Monitor for unexpected PHP executions originating from the web server process following page modifications.
